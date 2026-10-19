//! Every product-specific string in one place, so a fork renames the product by editing this file.

pub const PRODUCT: &str = "inveil";
pub const BLOCKED_PREFIX: &str = "[INVEIL BLOCKED]";
pub const BLOCKED_HEADER: &str = "x-inveil-blocked";
pub const CONFIG_FILE_NAME: &str = "inveil.toml";
pub const ENV_PREFIX: &str = "INVEIL_";
pub const KEYCHAIN_SERVICE_PREFIX: &str = "inveil";
pub const NOTIFICATION_TITLE: &str = "inveil";
pub const AUDIT_TARGET: &str = "inveil::audit";
pub const CA_DIR_NAME: &str = "ca";
pub const DEVICE_LABEL_ENV: &str = "INVEIL_DEVICE_LABEL";

pub fn keychain_service(backend_host: &str) -> String {
    format!("{KEYCHAIN_SERVICE_PREFIX}.{backend_host}")
}
