//! The detect stage for each body format: decode the text out of the body, scan it, and, when a `redact` rule fired,
//! rebuild the body with the redacted text. Pure functions; the proxy decides what to do with the result.
use crate::connect::{self, Frame, FrameTooLarge, COMPRESSED_FLAG};
use crate::decode::{decompress_detected, DecodeError};
use crate::form::FormBody;
use crate::protobuf::{Protobuf, ProtobufError};
use crate::scan::{Report, Scanner};
use contract::{Action, Format};
use serde_json::Value;

/// Stream messages shorter than this are control frames (acknowledgements, heartbeats) that carry no text.
const MIN_INSPECTED_MESSAGE_LEN: usize = 8;

#[derive(Debug, thiserror::Error)]
pub enum InspectError {
    #[error("request body is not valid JSON")]
    NotJson,
    #[error("request body is not protobuf we can read")]
    NotProtobuf(#[from] ProtobufError),
    #[error("a compressed message in a format we cannot read")]
    UnreadableCompression(#[from] DecodeError),
    #[error("a message with sensitive data in a format that cannot be redacted")]
    UnredactableSensitiveData,
    #[error("the redacted message does not fit a frame")]
    FrameTooLarge(#[from] FrameTooLarge),
}

#[derive(Debug, Default)]
pub struct Inspection {
    pub report: Report,
    /// The replacement body (or, for a stream frame, the whole replacement frame). `None` when nothing was redacted.
    pub redacted: Option<Vec<u8>>,
}

/// Inspects a complete, already decoded HTTP request body. Websocket and stream formats are read per message with
/// [`inspect_websocket_frame`] and [`inspect_connect_frame`], so as whole bodies they report nothing.
pub fn inspect(scanner: &Scanner, format: Format, body: &[u8]) -> Result<Inspection, InspectError> {
    match format {
        Format::Json => {
            let mut value =
                serde_json::from_slice::<Value>(body).map_err(|_| InspectError::NotJson)?;
            Ok(inspect_json(scanner, &mut value))
        }
        Format::Form => {
            let mut form = FormBody::parse(body);
            let mut texts = form.texts();
            let report = scanner.scan(&texts);
            let redacted = (report.wants_redaction() && scanner.redact(&mut texts)).then(|| {
                form.set_texts(&texts);
                form.encode()
            });
            Ok(Inspection { report, redacted })
        }
        Format::Protobuf | Format::ProtobufFramed => {
            let message = Protobuf::decode(body, format == Format::ProtobufFramed)?;
            inspect_protobuf(scanner, message)
        }
        Format::WebsocketJson | Format::ConnectStream => Ok(Inspection::default()),
    }
}

fn inspect_json(scanner: &Scanner, value: &mut Value) -> Inspection {
    let report = scanner.scan(value);
    let redacted =
        (report.wants_redaction() && scanner.redact(value)).then(|| value.to_string().into_bytes());
    Inspection { report, redacted }
}

fn inspect_protobuf(scanner: &Scanner, mut message: Protobuf) -> Result<Inspection, InspectError> {
    let mut texts = message.texts();
    let report = scanner.scan(&texts);
    if !report.wants_redaction() || !scanner.redact(&mut texts) {
        return Ok(Inspection {
            report,
            redacted: None,
        });
    }
    message.set_texts(&texts);
    Ok(Inspection {
        report,
        redacted: Some(message.encode()?),
    })
}

/// One text frame a browser sends over a WebSocket. `None` when the frame is not JSON, which passes untouched.
pub fn inspect_websocket_frame(scanner: &Scanner, text: &str) -> Option<Inspection> {
    let mut value = serde_json::from_str::<Value>(text).ok()?;
    Some(inspect_json(scanner, &mut value))
}

/// One frame of a Connect / gRPC-web stream. A redacted frame is sent uncompressed, with the flag cleared.
/// Text that is not protobuf is scanned as raw text; it cannot be redacted, so sensitive data in it is an error.
pub fn inspect_connect_frame(
    scanner: &Scanner,
    frame: &Frame,
    max_decoded_bytes: usize,
) -> Result<Inspection, InspectError> {
    if frame.message.len() < MIN_INSPECTED_MESSAGE_LEN {
        return Ok(Inspection::default());
    }
    let unpacked;
    let message: &[u8] = if frame.flags & COMPRESSED_FLAG != 0 {
        unpacked = decompress_detected(&frame.message, max_decoded_bytes)?;
        &unpacked
    } else {
        &frame.message
    };
    let Ok(decoded) = Protobuf::decode(message, false) else {
        let raw_text = Value::String(String::from_utf8_lossy(message).into_owned());
        let report = scanner.scan(&raw_text);
        if report
            .findings
            .iter()
            .any(|finding| finding.action != Action::Log)
        {
            return Err(InspectError::UnredactableSensitiveData);
        }
        return Ok(Inspection {
            report,
            redacted: None,
        });
    };
    let mut inspection = inspect_protobuf(scanner, decoded)?;
    if let Some(rewritten) = &inspection.redacted {
        let replacement = connect::encode(frame.flags & !COMPRESSED_FLAG, rewritten)?;
        inspection.redacted = Some(replacement.to_vec());
    }
    Ok(inspection)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::example_snapshot;
    use contract::PiiRule;

    fn scanner_redacting(rule_ids: &[&str]) -> Scanner {
        let mut pii: Vec<PiiRule> = example_snapshot().pii;
        for rule in pii
            .iter_mut()
            .filter(|rule| rule_ids.contains(&rule.id.as_str()))
        {
            rule.action = Action::Redact;
        }
        Scanner::from_rules(&pii, &[]).unwrap()
    }

    fn run(scanner: &Scanner, format: Format, body: &[u8]) -> Result<Inspection, InspectError> {
        inspect(scanner, format, body)
    }

    #[test]
    fn json_bodies_are_scanned_and_redacted() {
        let scanner = scanner_redacting(&["ssn"]);
        let body = br#"{"messages":[{"content":"my ssn is 123-45-6789"}]}"#;
        let inspection = run(&scanner, Format::Json, body).unwrap();
        assert_eq!(inspection.report.findings.len(), 1);
        let redacted = String::from_utf8(inspection.redacted.unwrap()).unwrap();
        assert!(redacted.contains("[REDACTED:ssn]") && !redacted.contains("123-45-6789"));
    }

    #[test]
    fn clean_json_has_no_findings_and_no_rewrite() {
        let inspection = run(
            &scanner_redacting(&["ssn"]),
            Format::Json,
            br#"{"a":"hello"}"#,
        )
        .unwrap();
        assert!(inspection.report.findings.is_empty() && inspection.redacted.is_none());
    }

    #[test]
    fn invalid_json_is_an_error() {
        assert!(matches!(
            run(&scanner_redacting(&[]), Format::Json, b"{nope"),
            Err(InspectError::NotJson)
        ));
    }

    #[test]
    fn form_values_are_scanned_and_redacted() {
        let scanner = scanner_redacting(&["ssn"]);
        let inspection = run(&scanner, Format::Form, b"f.req=ssn+123-45-6789&at=x").unwrap();
        assert_eq!(inspection.report.findings.len(), 1);
        let redacted = String::from_utf8(inspection.redacted.unwrap()).unwrap();
        assert!(redacted.contains("REDACTED") && redacted.ends_with("&at=x"));
    }

    #[test]
    fn protobuf_text_is_scanned_and_redacted() {
        let scanner = scanner_redacting(&["ssn"]);
        let mut body = vec![0x0a, 22];
        body.extend_from_slice(b"hello 123-45-6789 test");
        let inspection = run(&scanner, Format::Protobuf, &body).unwrap();
        assert_eq!(inspection.report.findings.len(), 1);
        let redacted = inspection.redacted.unwrap();
        assert!(String::from_utf8_lossy(&redacted).contains("[REDACTED:ssn]"));
        assert!(run(&scanner, Format::Protobuf, &[0x12, 0x7f, 0x01]).is_err());
    }

    #[test]
    fn websocket_and_stream_formats_are_read_per_message() {
        let scanner = scanner_redacting(&[]);
        let body = br#"{"a":"123-45-6789"}"#;
        assert!(run(&scanner, Format::WebsocketJson, body)
            .unwrap()
            .report
            .findings
            .is_empty());
        assert!(run(&scanner, Format::ConnectStream, body)
            .unwrap()
            .report
            .findings
            .is_empty());
    }

    #[test]
    fn websocket_frames_that_are_not_json_pass() {
        let scanner = scanner_redacting(&["ssn"]);
        assert!(inspect_websocket_frame(&scanner, "ping").is_none());
        let inspection = inspect_websocket_frame(&scanner, r#"{"t":"ssn 123-45-6789"}"#).unwrap();
        assert_eq!(inspection.report.findings.len(), 1);
        assert!(inspection.redacted.is_some());
    }

    fn stream_frame(flags: u8, message: &[u8]) -> Frame {
        let raw = connect::encode(flags, message).unwrap();
        Frame {
            flags,
            message: raw.slice(connect::FRAME_HEADER_LEN..),
            raw,
        }
    }

    #[test]
    fn stream_control_frames_are_not_inspected() {
        let frame = stream_frame(0, b"1234567");
        let inspection =
            inspect_connect_frame(&scanner_redacting(&["ssn"]), &frame, 1 << 20).unwrap();
        assert!(inspection.report.findings.is_empty());
    }

    #[test]
    fn a_redacted_compressed_stream_frame_is_sent_uncompressed() {
        use std::io::Write;
        let mut message = vec![0x0a, 22];
        message.extend_from_slice(b"hello 123-45-6789 test");
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&message).unwrap();
        let frame = stream_frame(COMPRESSED_FLAG, &encoder.finish().unwrap());
        let inspection =
            inspect_connect_frame(&scanner_redacting(&["ssn"]), &frame, 1 << 20).unwrap();
        let replacement = inspection.redacted.unwrap();
        assert_eq!(replacement[0], 0, "the compressed flag is cleared");
        assert!(String::from_utf8_lossy(&replacement).contains("[REDACTED:ssn]"));
    }

    #[test]
    fn a_stream_frame_in_an_unknown_compression_is_an_error() {
        let frame = stream_frame(COMPRESSED_FLAG, b"neither gzip nor zstd");
        assert!(matches!(
            inspect_connect_frame(&scanner_redacting(&[]), &frame, 1 << 20),
            Err(InspectError::UnreadableCompression(_))
        ));
    }

    #[test]
    fn raw_text_in_a_stream_blocks_unless_it_only_logs() {
        let scanner = scanner_redacting(&[]);
        let sensitive = stream_frame(0, b"\xff\xffplain text 123-45-6789 here");
        assert!(matches!(
            inspect_connect_frame(&scanner, &sensitive, 1 << 20),
            Err(InspectError::UnredactableSensitiveData)
        ));
        let logged = stream_frame(0, b"\xff\xffplain mail bob@example.com here");
        let inspection = inspect_connect_frame(&scanner, &logged, 1 << 20).unwrap();
        assert_eq!(inspection.report.findings.len(), 1);
    }
}
