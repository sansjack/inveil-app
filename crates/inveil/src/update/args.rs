//! Minimal flag parsing for the updater subcommands: `--flag value`, `--switch` and positional arguments.
use super::UpdateError;
use std::collections::{BTreeMap, BTreeSet};

pub struct Arguments {
    values: BTreeMap<String, Vec<String>>,
    switches: BTreeSet<String>,
    pub positional: Vec<String>,
}

impl Arguments {
    pub fn parse(
        args: &[String],
        value_flags: &[&str],
        switch_flags: &[&str],
    ) -> Result<Self, UpdateError> {
        let mut parsed = Self {
            values: BTreeMap::new(),
            switches: BTreeSet::new(),
            positional: vec![],
        };
        let mut remaining = args.iter();
        while let Some(argument) = remaining.next() {
            if switch_flags.contains(&argument.as_str()) {
                parsed.switches.insert(argument.clone());
                continue;
            }
            if value_flags.contains(&argument.as_str()) {
                let value = remaining
                    .next()
                    .ok_or_else(|| UpdateError::Usage(format!("{argument} needs a value")))?;
                parsed
                    .values
                    .entry(argument.clone())
                    .or_default()
                    .push(value.clone());
                continue;
            }
            if argument.starts_with("--") {
                return Err(UpdateError::Usage(format!("unknown flag {argument}")));
            }
            parsed.positional.push(argument.clone());
        }
        Ok(parsed)
    }

    pub fn value(&self, flag: &str) -> Option<&str> {
        self.values(flag).first().map(String::as_str)
    }

    pub fn values(&self, flag: &str) -> &[String] {
        self.values.get(flag).map_or(&[], Vec::as_slice)
    }

    pub fn required(&self, flag: &str) -> Result<&str, UpdateError> {
        self.value(flag)
            .ok_or_else(|| UpdateError::Usage(format!("{flag} is required")))
    }

    pub fn has(&self, flag: &str) -> bool {
        self.switches.contains(flag)
    }

    pub fn single_positional(&self, name: &str) -> Result<&str, UpdateError> {
        match self.positional.as_slice() {
            [only] => Ok(only),
            _ => Err(UpdateError::Usage(format!("expected exactly one {name}"))),
        }
    }
}
