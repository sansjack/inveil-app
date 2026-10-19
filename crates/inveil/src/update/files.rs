//! Small filesystem helpers shared by the updater. Everything the updater creates is owner-only.
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

#[cfg(unix)]
const PRIVATE_DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;
#[cfg(unix)]
const EXECUTABLE_MODE: u32 = 0o755;

#[derive(Debug, thiserror::Error)]
#[error("cannot {action} {}: {source}", path.display())]
pub struct FileError {
    action: &'static str,
    path: PathBuf,
    source: io::Error,
}

pub fn failed(action: &'static str, path: &Path) -> impl FnOnce(io::Error) -> FileError {
    let path = path.to_path_buf();
    move |source| FileError {
        action,
        path,
        source,
    }
}

pub fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Fails if the file already exists, so an existing key or download is never overwritten or followed through a link.
pub fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(PRIVATE_FILE_MODE);
    }
    options.open(path)
}

pub fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_DIR_MODE))?;
    }
    Ok(())
}

#[cfg(unix)]
pub fn make_executable(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(EXECUTABLE_MODE))
}

#[cfg(not(unix))]
pub fn make_executable(_path: &Path) -> io::Result<()> {
    Ok(())
}
