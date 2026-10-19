use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

/// Unix permission bits for what this program writes; ignored where there are none (Windows uses ACLs).
pub const PRIVATE_FILE_MODE: u32 = 0o600;
pub const PUBLIC_FILE_MODE: u32 = 0o644;
pub const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
pub const PUBLIC_DIRECTORY_MODE: u32 = 0o755;

/// A poisoned lock only means another thread panicked while holding it; the data is still usable here.
pub fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

pub fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Where every local listener binds and every local check connects.
pub fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

/// Replaces `path` with `contents` all at once, readable by the owner only. See [`write_atomically_with_mode`].
pub fn write_atomically(path: &Path, contents: &[u8]) -> io::Result<()> {
    write_atomically_with_mode(path, contents, PRIVATE_FILE_MODE)
}

/// Replaces `path` with `contents` all at once: written to a uniquely named file next to it with exactly the permission
/// bits `mode` (whatever the umask), flushed to disk, renamed over the target, and the directory entry flushed too, so a crash leaves either the
/// old or the new file. A `path` that is a symlink is refused rather than followed or replaced, and the temporary file
/// is created exclusively, so a symlink planted in its place is never followed either.
#[cfg_attr(not(unix), allow(unused_variables))]
pub fn write_atomically_with_mode(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "the path has no file name"))?;
    refuse_symlink(path)?;
    let temporary = path.with_file_name(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        uuid::Uuid::new_v4()
    ));
    let result =
        write_flushed(&temporary, contents, mode).and_then(|()| fs::rename(&temporary, path));
    if let Err(error) = result {
        if let Err(cleanup) = fs::remove_file(&temporary) {
            if cleanup.kind() != io::ErrorKind::NotFound {
                tracing::warn!(path = %temporary.display(), %cleanup, "cannot remove temporary file");
            }
        }
        return Err(error);
    }
    flush_directory(path)
}

/// Fails when `path` exists and is a symlink; a missing path is fine.
pub fn refuse_symlink(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} is a symlink; refusing to follow or replace it",
                path.display()
            ),
        )),
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// Creates `path` and any missing parents with the permission bits `mode`. Existing directories keep theirs.
#[cfg_attr(not(unix), allow(unused_variables))]
pub fn create_directory(path: &Path, mode: u32) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(mode);
    }
    builder.create(path)
}

/// Opens a log for appending, creating it readable by the owner only. A log that already exists is tightened to match.
pub fn open_private_append(path: &Path) -> io::Result<fs::File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(PRIVATE_FILE_MODE);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;
    }
    Ok(file)
}

#[cfg_attr(not(unix), allow(unused_variables))]
fn write_flushed(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
    }
    file.write_all(contents)?;
    file.sync_all()
}

#[cfg(unix)]
fn flush_directory(path: &Path) -> io::Result<()> {
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    fs::File::open(directory)?.sync_all()
}

#[cfg(not(unix))]
fn flush_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_writes_replace_the_file_and_leave_no_temporary_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        write_atomically(&path, b"first").unwrap();
        write_atomically(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
        let names: Vec<_> = fs::read_dir(directory.path()).unwrap().collect();
        assert_eq!(names.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_writes_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        write_atomically(&path, b"secret").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, PRIVATE_FILE_MODE);
    }

    #[cfg(unix)]
    #[test]
    fn an_explicit_mode_is_applied_whatever_the_umask() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("shared.json");
        write_atomically_with_mode(&path, b"{}", PUBLIC_FILE_MODE).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, PUBLIC_FILE_MODE);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_target_is_refused_and_left_alone() {
        let directory = tempfile::tempdir().unwrap();
        let real = directory.path().join("real.json");
        fs::write(&real, "keep").unwrap();
        let link = directory.path().join("link.json");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let error = write_atomically(&link, b"changed").unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(fs::read_to_string(&real).unwrap(), "keep");
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn directories_get_the_requested_mode_and_logs_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let nested = directory.path().join("a").join("b");
        create_directory(&nested, PRIVATE_DIRECTORY_MODE).unwrap();
        for created in [directory.path().join("a"), nested.clone()] {
            let mode = fs::metadata(created).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, PRIVATE_DIRECTORY_MODE);
        }

        let log = nested.join("audit.jsonl");
        fs::write(&log, "old\n").unwrap();
        fs::set_permissions(&log, fs::Permissions::from_mode(0o644)).unwrap();
        open_private_append(&log)
            .unwrap()
            .write_all(b"new\n")
            .unwrap();
        assert_eq!(
            fs::metadata(&log).unwrap().permissions().mode() & 0o777,
            PRIVATE_FILE_MODE
        );
        assert_eq!(fs::read_to_string(&log).unwrap(), "old\nnew\n");
    }

    #[test]
    fn a_failed_atomic_write_leaves_the_target_untouched() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        write_atomically(&path, b"kept").unwrap();
        let missing = directory.path().join("absent").join("state.json");
        assert!(write_atomically(&missing, b"lost").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"kept");
    }
}
