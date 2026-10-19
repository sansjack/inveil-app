#![no_main]
use contract::Snapshot;
use engine::{validate, Policy};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(snapshot) = serde_json::from_slice::<Snapshot>(data) else {
        return;
    };
    if validate(&snapshot).is_err() {
        return;
    }
    let _ = Policy::build(&snapshot, &snapshot.settings.deny, &snapshot.ca_domains);
});
