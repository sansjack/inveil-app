//! Where the updater keeps things relative to the installed executable. All of it is on the same filesystem as the
//! executable so the final move is an atomic rename.
use super::files::suffixed;
use std::path::{Path, PathBuf};

pub const PREVIOUS_NAME: &str = "inveil.prev";
pub const STAGING_DIR_NAME: &str = ".inveil-update";
const STAGED_NAME: &str = "inveil.download";
const PARTIAL_SUFFIX: &str = ".partial";
const ROLLBACK_NAME: &str = ".inveil-rollback";
const PENDING_NAME: &str = ".inveil-update-pending";
pub const REPLACED_SUFFIX: &str = ".old";

#[derive(Clone, Debug)]
pub struct InstallLayout {
    pub install_path: PathBuf,
    pub install_dir: PathBuf,
}

impl InstallLayout {
    pub fn new(install_path: &Path) -> Option<Self> {
        Some(Self {
            install_path: install_path.to_path_buf(),
            install_dir: install_path.parent()?.to_path_buf(),
        })
    }

    pub fn previous(&self) -> PathBuf {
        self.install_dir.join(PREVIOUS_NAME)
    }

    pub fn staging_dir(&self) -> PathBuf {
        self.install_dir.join(STAGING_DIR_NAME)
    }

    pub fn staged(&self) -> PathBuf {
        self.staging_dir().join(STAGED_NAME)
    }

    pub fn partial(&self) -> PathBuf {
        suffixed(&self.staged(), PARTIAL_SUFFIX)
    }

    pub fn rollback_copy(&self) -> PathBuf {
        self.install_dir.join(ROLLBACK_NAME)
    }

    pub fn pending(&self) -> PathBuf {
        self.install_dir.join(PENDING_NAME)
    }

    pub fn replaced(&self) -> PathBuf {
        suffixed(&self.install_path, REPLACED_SUFFIX)
    }
}
