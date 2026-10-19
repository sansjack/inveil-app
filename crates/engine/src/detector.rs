use contract::Action;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::LazyLock;

static SALT: LazyLock<RandomState> = LazyLock::new(RandomState::new);

/// Hash of a matched text, salted per process: repeats can be correlated in a log without storing the secret.
pub fn salted_hash(text: &str) -> u64 {
    SALT.hash_one(text)
}

/// One match of a detector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub rule_id: String,
    pub label: String,
    pub location: String,
    pub hash: u64,
    pub action: Action,
}

/// An interchangeable way of finding sensitive data in a piece of text.
pub trait Detector: Send + Sync {
    fn detect(&self, text: &str, location: &str) -> Vec<Finding>;

    /// The text with every match of a `redact` rule replaced, or `None` when nothing changed.
    fn redact(&self, _text: &str) -> Option<String> {
        None
    }
}
