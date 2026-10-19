//! `application/x-www-form-urlencoded` bodies, whose chat text sits in the values.
use serde_json::Value;

/// Values are scanned as plain text, nested JSON included. A pattern broken up by JSON escapes (`\uXXXX`) is
/// missed; the redaction placeholder has no characters JSON would need to escape.
pub struct FormBody {
    pairs: Vec<(String, String)>,
}

impl FormBody {
    pub fn parse(body: &[u8]) -> Self {
        Self {
            pairs: form_urlencoded::parse(body).into_owned().collect(),
        }
    }

    /// The values as a JSON array of strings, for the scanner.
    pub fn texts(&self) -> Value {
        Value::Array(
            self.pairs
                .iter()
                .map(|(_, value)| Value::String(value.clone()))
                .collect(),
        )
    }

    /// Writes back values changed by redaction. `texts` must be a (modified) value from [`FormBody::texts`].
    pub fn set_texts(&mut self, texts: &Value) {
        let Some(values) = texts.as_array() else {
            return;
        };
        for ((_, value), redacted) in self.pairs.iter_mut().zip(values) {
            if let Some(redacted) = redacted.as_str() {
                value.clear();
                value.push_str(redacted);
            }
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&self.pairs)
            .finish()
            .into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn exposes_values_and_writes_redacted_ones_back() {
        let mut form = FormBody::parse(b"f.req=ssn+123-45-6789&at=token");
        assert_eq!(form.texts(), json!(["ssn 123-45-6789", "token"]));
        form.set_texts(&json!(["ssn [REDACTED:ssn]", "token"]));
        assert_eq!(
            String::from_utf8(form.encode()).unwrap(),
            "f.req=ssn+%5BREDACTED%3Assn%5D&at=token"
        );
    }

    #[test]
    fn an_empty_body_has_no_texts() {
        assert_eq!(FormBody::parse(b"").texts(), json!([]));
    }
}
