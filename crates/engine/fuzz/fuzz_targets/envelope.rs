#![no_main]
use engine::{verify_envelope, PinnedKey, Role, Trust};
use libfuzzer_sys::fuzz_target;

const FIXED_NOW: u64 = 1_800_000_000;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let trust = Trust {
        keys: vec![PinnedKey {
            key_id: "fuzz".into(),
            public_key: [7; 32],
        }],
        roots: vec![PinnedKey {
            key_id: "root".into(),
            public_key: [9; 32],
        }],
..Trust::default()
    };
    for role in [Role::Policy, Role::Update] {
        let result = verify_envelope::<serde_json::Value>(role, &trust, 1, FIXED_NOW, text);
        assert!(result.is_err(), "unsigned input must never verify");
    }
});
