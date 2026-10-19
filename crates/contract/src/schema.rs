//! Generates the JSON Schema files in `contract/v1` from the Rust types and fails when the committed files differ.
//! Run with `UPDATE_SCHEMAS=1 cargo test -p contract schema` to rewrite them after changing a type.
use crate::{EnrollRequest, EnrollResponse, SignedEnvelope, Snapshot, UpdateManifest, UsageBatch};
use schemars::{schema_for, JsonSchema};
use std::path::PathBuf;

fn schema_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contract/v1")
}

fn rendered<T: JsonSchema>() -> String {
    let schema = schema_for!(T);
    let mut text = serde_json::to_string_pretty(&schema).unwrap();
    text.push('\n');
    text
}

#[test]
fn schema() {
    let update = std::env::var_os("UPDATE_SCHEMAS").is_some();
    let schemas = [
        ("Snapshot", rendered::<Snapshot>()),
        ("UpdateManifest", rendered::<UpdateManifest>()),
        ("SignedEnvelope", rendered::<SignedEnvelope>()),
        ("EnrollRequest", rendered::<EnrollRequest>()),
        ("EnrollResponse", rendered::<EnrollResponse>()),
        ("UsageBatch", rendered::<UsageBatch>()),
    ];
    let mut drifted = vec![];
    for (name, expected) in schemas {
        let path = schema_directory().join(format!("{name}.schema.json"));
        if update {
            std::fs::write(&path, &expected).unwrap();
            continue;
        }
        if std::fs::read_to_string(&path).ok().as_deref() != Some(expected.as_str()) {
            drifted.push(name);
        }
    }
    assert!(
        drifted.is_empty(),
        "schemas out of date: {drifted:?}; run `UPDATE_SCHEMAS=1 cargo test -p contract schema`"
    );
}
