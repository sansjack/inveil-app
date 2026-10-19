//! `inveil enroll --bundle`: trades a one-time enrollment token for a device credential. The backend derives the
//! organisation from the token, so the client never states one it could forge.
use super::credentials::{save_device_credential, save_org_id};
use super::http::{check_status, client, endpoint, read_json, unreachable};
use super::BackendError;
use crate::config::{AuthConfig, Config, PinnedKeyConfig};
use contract::{EnrollRequest, EnrollResponse};
use serde::Deserialize;

/// The same fields as the local bootstrap configuration, written by the install script or by hand.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentBundle {
    pub backend_url: String,
    pub pinned_keys: Vec<PinnedKeyConfig>,
    pub enrollment_token: String,
    #[serde(default)]
    pub auth: Option<AuthConfig>,
    #[serde(default)]
    pub update: Option<BundleUpdate>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleUpdate {
    pub feed_url: Option<String>,
    #[serde(default, alias = "keys")]
    pub pinned_keys: Vec<PinnedKeyConfig>,
    /// Distinct update keys a manifest needs; the official bundle sets 2.
    #[serde(default)]
    pub min_signatures: Option<usize>,
}

impl EnrollmentBundle {
    pub fn parse(text: &str) -> Result<Self, BackendError> {
        serde_json::from_str(text).map_err(|error| BackendError::BadResponse(error.to_string()))
    }

    /// Merges the bundle's update settings into the `[update]` table of an existing configuration, leaving every other
    /// key in it (such as a `feed_url` the bundle does not mention) as it was.
    pub fn record_update(&self, table: &mut toml::Table) -> Result<(), toml::ser::Error> {
        let Some(update) = &self.update else {
            return Ok(());
        };
        let section = table
            .entry("update")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        if !section.is_table() {
            *section = toml::Value::Table(toml::Table::new());
        }
        let Some(section) = section.as_table_mut() else {
            return Ok(());
        };
        if let Some(feed_url) = &update.feed_url {
            section.insert("feed_url".into(), toml::Value::String(feed_url.clone()));
        }
        if !update.pinned_keys.is_empty() {
            section.insert(
                "pinned_keys".into(),
                toml::Value::try_from(&update.pinned_keys)?,
            );
        }
        if let Some(min_signatures) = update.min_signatures {
            section.insert(
                "min_signatures".into(),
                toml::Value::try_from(min_signatures)?,
            );
        }
        Ok(())
    }
}

/// Redeems the token and stores the device credential and the organisation it names in the OS keychain. `config`
/// already carries the bundle's backend URL and pinned keys, so the same URL validation applies as for any other
/// configuration.
pub async fn enroll(config: &Config, token: &str) -> Result<(), BackendError> {
    let base_url = config
        .backend
        .url
        .as_deref()
        .ok_or_else(|| BackendError::BadUrl("backend.url is not set".into()))?;
    let request = EnrollRequest {
        token: token.to_string(),
        client_version: env!("CARGO_PKG_VERSION").to_string(),
        device_label: std::env::var(crate::brand::DEVICE_LABEL_ENV).ok(),
    };
    let response = client()?
        .post(endpoint(base_url, &config.backend.enroll_path)?)
        .json(&request)
        .send()
        .await
        .map_err(unreachable)?;
    check_status(&response)?;
    let granted: EnrollResponse = read_json(response).await?;
    save_device_credential(config, &granted.device_credential)?;
    save_org_id(config, granted.org_id.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::UpdateConfig;

    #[test]
    fn a_bundle_with_unknown_fields_is_refused() {
        let bundle = r#"{"backend_url":"https://b.example","pinned_keys":[],"enrollment_token":"t","extra":1}"#;
        assert!(EnrollmentBundle::parse(bundle).is_err());
    }

    const BUNDLE_WITH_TWO_UPDATE_KEYS: &str = r#"{
        "backend_url": "https://b.example",
        "pinned_keys": [{"key_id": "k1", "public_key": "AAAA"}],
        "enrollment_token": "tok",
        "update": {"feed_url": "https://u.example/manifest.json", "keys": [
            {"key_id": "u1", "public_key": "u1u1u1u1u1u1u1u1u1u1u1u1u1u1u1u1u1u1u1u1u1s="},
            {"key_id": "u2", "public_key": "u2u2u2u2u2u2u2u2u2u2u2u2u2u2u2u2u2u2u2u2u2s="}
        ]}
    }"#;

    fn recorded(bundle: &str, existing: &str) -> toml::Table {
        let mut table: toml::Table = existing.parse().unwrap();
        EnrollmentBundle::parse(bundle)
            .unwrap()
            .record_update(&mut table)
            .unwrap();
        table
    }

    fn update_config_of(table: toml::Table) -> UpdateConfig {
        let config: Config = toml::Value::Table(table).try_into().unwrap();
        config.update
    }

    #[test]
    fn a_bundle_carries_backend_keys_token_and_update_feed() {
        let bundle = r#"{
            "backend_url": "https://b.example",
            "pinned_keys": [{"key_id": "k1", "public_key": "AAAA"}],
            "enrollment_token": "tok",
            "update": {"feed_url": "https://u.example/manifest.json", "min_signatures": 2, "keys": [{"key_id": "u1", "public_key": "BBBB"}]}
        }"#;
        let parsed = EnrollmentBundle::parse(bundle).unwrap();
        assert_eq!(parsed.enrollment_token, "tok");
        let update = update_config_of(recorded(bundle, ""));
        assert_eq!(update.pinned_keys[0].key_id, "u1");
        assert_eq!(update.min_signatures, Some(2));
    }

    #[test]
    fn a_bundle_that_pins_two_update_keys_without_a_floor_requires_two_signatures() {
        let update = update_config_of(recorded(BUNDLE_WITH_TWO_UPDATE_KEYS, ""));
        assert_eq!(update.min_signatures, None);
        assert_eq!(update.required_signatures(), 2);
    }

    #[test]
    fn recording_a_bundle_keeps_the_settings_it_does_not_mention() {
        let existing = "[update]\nmode = \"download\"\nfeed_url = \"https://own.example/feed.json\"\ncheck_hours = 6\n";
        let bundle = r#"{
            "backend_url": "https://b.example", "pinned_keys": [], "enrollment_token": "t",
            "update": {"keys": [{"key_id": "u1", "public_key": "BBBB"}]}
        }"#;
        let update = update_config_of(recorded(bundle, existing));
        assert_eq!(
            update.feed_url.as_deref(),
            Some("https://own.example/feed.json")
        );
        assert_eq!(update.check_hours, 6);
        assert_eq!(update.pinned_keys.len(), 1);
    }

    #[test]
    fn a_bundle_feed_url_replaces_an_existing_one() {
        let existing = "[update]\nfeed_url = \"https://old.example/feed.json\"\n";
        let update = update_config_of(recorded(BUNDLE_WITH_TWO_UPDATE_KEYS, existing));
        assert_eq!(
            update.feed_url.as_deref(),
            Some("https://u.example/manifest.json")
        );
    }
}
