//! Streams the raw binary named in the manifest into the private staging directory with a hard size limit and a
//! running SHA-256. Nothing outside the staging directory is touched, and a failed download leaves nothing behind.
use super::fetch::{FetchError, Fetcher};
use super::files::{create_private_dir, create_private_file, failed, FileError};
use super::layout::InstallLayout;
use contract::Artifact;
use engine::signing::hex_lower;
use ring::digest::{Context, SHA256};
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Write};
use std::path::Path;
use std::time::Duration;

const MAX_BINARY_BYTES: u64 = 512 * 1024 * 1024;
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const CHUNK_BYTES: usize = 64 * 1024;
const SHA256_HEX_LEN: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum DownloadError {
    #[error(transparent)]
    Fetch(#[from] FetchError),
    #[error(transparent)]
    File(#[from] FileError),
    #[error("manifest lists an unusable binary: {0}")]
    InvalidArtifact(&'static str),
    #[error("download is larger than the {expected} bytes the manifest signed")]
    SizeExceeded { expected: u64 },
    #[error("download ended after {received} of {expected} bytes")]
    Truncated { expected: u64, received: u64 },
    #[error("connection failed during download: {0}")]
    Interrupted(std::io::Error),
    #[error("downloaded binary hash {actual} does not match the signed hash {expected}")]
    HashMismatch { expected: String, actual: String },
}

pub fn hash_file(path: &Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut context = Context::new(&SHA256);
    let mut chunk = [0u8; CHUNK_BYTES];
    loop {
        let read = file.read(&mut chunk)?;
        if read == 0 {
            return Ok(hex_lower(context.finish().as_ref()));
        }
        context.update(&chunk[..read]);
    }
}

fn validate(artifact: &Artifact) -> Result<(), DownloadError> {
    if artifact.size == 0 || artifact.size > MAX_BINARY_BYTES {
        return Err(DownloadError::InvalidArtifact("size is zero or too large"));
    }
    let is_lower_hex = artifact
        .sha256
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if artifact.sha256.len() != SHA256_HEX_LEN || !is_lower_hex {
        return Err(DownloadError::InvalidArtifact(
            "sha256 is not 64 lower-case hex characters",
        ));
    }
    Ok(())
}

fn prepare_staging_dir(layout: &InstallLayout) -> Result<(), DownloadError> {
    let dir = layout.staging_dir();
    match fs::symlink_metadata(&dir) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(DownloadError::InvalidArtifact(
            "staging path exists and is not a directory",
        )),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            create_private_dir(&dir).map_err(failed("create", &dir))?;
            Ok(())
        }
        Err(error) => Err(failed("inspect", &dir)(error).into()),
    }
}

fn remove_if_present(path: &Path) -> Result<(), DownloadError> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != ErrorKind::NotFound => {
            Err(failed("remove", path)(error).into())
        }
        _ => Ok(()),
    }
}

fn is_already_staged(layout: &InstallLayout, artifact: &Artifact) -> bool {
    hash_file(&layout.staged()).is_ok_and(|hash| hash == artifact.sha256)
}

/// Leaves a verified, non-executable `inveil.download` in the staging directory.
pub fn stage(
    fetcher: &dyn Fetcher,
    artifact: &Artifact,
    layout: &InstallLayout,
) -> Result<(), DownloadError> {
    validate(artifact)?;
    prepare_staging_dir(layout)?;
    if is_already_staged(layout, artifact) {
        return Ok(());
    }
    remove_if_present(&layout.staged())?;
    remove_if_present(&layout.partial())?;

    let result = download_verified(fetcher, artifact, layout);
    if result.is_err() {
        let staging = layout.staging_dir();
        fs::remove_dir_all(&staging).map_err(failed("remove", &staging))?;
    }
    result
}

fn download_verified(
    fetcher: &dyn Fetcher,
    artifact: &Artifact,
    layout: &InstallLayout,
) -> Result<(), DownloadError> {
    let mut reader = fetcher.open(&artifact.url, DOWNLOAD_TIMEOUT)?;
    let partial = layout.partial();
    let mut file = create_private_file(&partial).map_err(failed("create", &partial))?;

    let mut context = Context::new(&SHA256);
    let mut received = 0u64;
    let mut chunk = [0u8; CHUNK_BYTES];
    loop {
        let read = reader
            .read(&mut chunk)
            .map_err(DownloadError::Interrupted)?;
        if read == 0 {
            break;
        }
        received += read as u64;
        if received > artifact.size {
            return Err(DownloadError::SizeExceeded {
                expected: artifact.size,
            });
        }
        context.update(&chunk[..read]);
        file.write_all(&chunk[..read])
            .map_err(failed("write", &partial))?;
    }
    if received < artifact.size {
        return Err(DownloadError::Truncated {
            expected: artifact.size,
            received,
        });
    }

    let actual = hex_lower(context.finish().as_ref());
    if actual != artifact.sha256 {
        return Err(DownloadError::HashMismatch {
            expected: artifact.sha256.clone(),
            actual,
        });
    }
    file.sync_all().map_err(failed("flush", &partial))?;
    fs::rename(&partial, layout.staged()).map_err(failed("rename", &partial))?;
    Ok(())
}
