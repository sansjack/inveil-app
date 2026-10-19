//! Just enough protobuf to scan and redact chat text without the message definitions: find the text strings, hand
//! them to the scanner as a JSON array, write the (possibly redacted) strings back, and re-encode with corrected
//! length prefixes. Everything that is not text is kept byte for byte.
use crate::connect::{COMPRESSED_FLAG, FRAME_HEADER_LEN, MAX_FRAME_BYTES};
use serde_json::Value;

const MAX_VARINT_BYTES: u32 = 10;
const VARINT_PAYLOAD_BITS: u32 = 7;
const VARINT_PAYLOAD_MASK: u8 = 0x7f;
const VARINT_CONTINUATION_BIT: u8 = 0x80;
const WIRE_TYPE_MASK: u64 = 7;
const WIRE_VARINT: u64 = 0;
const WIRE_FIXED64: u64 = 1;
const WIRE_LENGTH_DELIMITED: u64 = 2;
const WIRE_FIXED32: u64 = 5;
const FIELD_NUMBER_SHIFT: u32 = 3;
/// A length-delimited field nested deeper than this is kept as opaque bytes, so hostile input cannot exhaust the stack.
const MAX_NESTING_DEPTH: usize = 16;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtobufError {
    #[error("the bytes are not valid protobuf")]
    Malformed,
    #[error("a frame is compressed and cannot be read")]
    CompressedFrame,
    #[error("a frame is larger than {MAX_FRAME_BYTES} bytes")]
    FrameTooLarge,
}

/// There is no schema, so text and nested messages are told apart by looking at the bytes: printable UTF-8 is text,
/// anything with control bytes that parses cleanly is a nested message. A nested message made only of printable
/// bytes is mistaken for text, and redacting inside it would corrupt it; chat sends seen so far do not hit this.
enum Content {
    Text(String),
    Message(Vec<Field>),
    Bytes(Vec<u8>),
}

enum Payload {
    Varint(u64),
    Fixed64([u8; 8]),
    Fixed32([u8; 4]),
    Length(Content),
}

struct Field {
    tag: u64,
    payload: Payload,
}

/// A protobuf body. Connect and gRPC-web wrap each message in a 5 byte header (flags, length); `framed` bodies keep
/// every frame, unframed bodies hold exactly one.
pub struct Protobuf {
    framed: bool,
    frames: Vec<(u8, Vec<Field>)>,
}

impl Protobuf {
    pub fn decode(bytes: &[u8], framed: bool) -> Result<Self, ProtobufError> {
        if !framed {
            return Ok(Self {
                framed,
                frames: vec![(0, parse_fields(bytes, 0)?)],
            });
        }
        let mut frames = Vec::new();
        let mut rest = bytes;
        while !rest.is_empty() {
            let header = rest
                .get(..FRAME_HEADER_LEN)
                .ok_or(ProtobufError::Malformed)?;
            let flags = header[0];
            let announced = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
            let length = usize::try_from(announced).map_err(|_| ProtobufError::FrameTooLarge)?;
            if length > MAX_FRAME_BYTES {
                return Err(ProtobufError::FrameTooLarge);
            }
            let frame_end = FRAME_HEADER_LEN + length;
            let payload = rest
                .get(FRAME_HEADER_LEN..frame_end)
                .ok_or(ProtobufError::Malformed)?;
            if flags & COMPRESSED_FLAG != 0 {
                return Err(ProtobufError::CompressedFrame);
            }
            frames.push((flags, parse_fields(payload, 0)?));
            rest = &rest[frame_end..];
        }
        Ok(Self { framed, frames })
    }

    /// The text strings, as nested JSON arrays that mirror the message structure (non-text fields are null), so the
    /// normal scanner can walk and redact them. Pass the result to [`Protobuf::set_texts`].
    pub fn texts(&self) -> Value {
        Value::Array(
            self.frames
                .iter()
                .map(|(_, fields)| fields_to_value(fields))
                .collect(),
        )
    }

    /// Writes back strings changed by redaction. `texts` must be a (modified) value from [`Protobuf::texts`].
    pub fn set_texts(&mut self, texts: &Value) {
        let Some(frame_values) = texts.as_array() else {
            return;
        };
        for ((_, fields), value) in self.frames.iter_mut().zip(frame_values) {
            apply_value(fields, value);
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtobufError> {
        let mut out = Vec::new();
        for (flags, fields) in &self.frames {
            let body = encode_fields(fields);
            if self.framed {
                let length = u32::try_from(body.len()).map_err(|_| ProtobufError::FrameTooLarge)?;
                out.push(*flags);
                out.extend_from_slice(&length.to_be_bytes());
            }
            out.extend_from_slice(&body);
        }
        Ok(out)
    }
}

fn read_varint(bytes: &[u8], at: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for index in 0..MAX_VARINT_BYTES {
        let byte = *bytes.get(*at)?;
        *at += 1;
        value |= u64::from(byte & VARINT_PAYLOAD_MASK) << (index * VARINT_PAYLOAD_BITS);
        if byte & VARINT_CONTINUATION_BIT == 0 {
            return Some(value);
        }
    }
    None
}

fn write_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= u64::from(VARINT_CONTINUATION_BIT) {
        out.push((value & u64::from(VARINT_PAYLOAD_MASK)) as u8 | VARINT_CONTINUATION_BIT);
        value >>= VARINT_PAYLOAD_BITS;
    }
    out.push(value as u8);
}

fn take<'a>(bytes: &'a [u8], at: &mut usize, length: usize) -> Option<&'a [u8]> {
    let end = at.checked_add(length)?;
    let taken = bytes.get(*at..end)?;
    *at = end;
    Some(taken)
}

/// Strict: the whole input must be well-formed fields.
fn parse_fields(bytes: &[u8], depth: usize) -> Result<Vec<Field>, ProtobufError> {
    parse_fields_opt(bytes, depth).ok_or(ProtobufError::Malformed)
}

fn parse_fields_opt(bytes: &[u8], depth: usize) -> Option<Vec<Field>> {
    let mut fields = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let tag = read_varint(bytes, &mut at)?;
        if tag >> FIELD_NUMBER_SHIFT == 0 {
            return None;
        }
        let payload = match tag & WIRE_TYPE_MASK {
            WIRE_VARINT => Payload::Varint(read_varint(bytes, &mut at)?),
            WIRE_FIXED64 => Payload::Fixed64(take(bytes, &mut at, 8)?.try_into().ok()?),
            WIRE_LENGTH_DELIMITED => {
                let length = usize::try_from(read_varint(bytes, &mut at)?).ok()?;
                Payload::Length(classify(take(bytes, &mut at, length)?, depth))
            }
            WIRE_FIXED32 => Payload::Fixed32(take(bytes, &mut at, 4)?.try_into().ok()?),
            _ => return None,
        };
        fields.push(Field { tag, payload });
    }
    Some(fields)
}

fn classify(raw: &[u8], depth: usize) -> Content {
    if let Ok(text) = std::str::from_utf8(raw) {
        let printable = !text
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'));
        if printable && !text.is_empty() {
            return Content::Text(text.to_string());
        }
    }
    if depth >= MAX_NESTING_DEPTH {
        return Content::Bytes(raw.to_vec());
    }
    match parse_fields_opt(raw, depth + 1) {
        Some(fields) if !fields.is_empty() => Content::Message(fields),
        _ => Content::Bytes(raw.to_vec()),
    }
}

fn fields_to_value(fields: &[Field]) -> Value {
    Value::Array(
        fields
            .iter()
            .map(|field| match &field.payload {
                Payload::Length(Content::Text(text)) => Value::String(text.clone()),
                Payload::Length(Content::Message(inner)) => fields_to_value(inner),
                _ => Value::Null,
            })
            .collect(),
    )
}

fn apply_value(fields: &mut [Field], value: &Value) {
    let Some(values) = value.as_array() else {
        return;
    };
    for (field, value) in fields.iter_mut().zip(values) {
        match (&mut field.payload, value) {
            (Payload::Length(Content::Text(text)), Value::String(new_text)) => {
                text.clone_from(new_text);
            }
            (Payload::Length(Content::Message(inner)), value) => apply_value(inner, value),
            _ => {}
        }
    }
}

fn encode_fields(fields: &[Field]) -> Vec<u8> {
    let mut out = Vec::new();
    for field in fields {
        write_varint(field.tag, &mut out);
        match &field.payload {
            Payload::Varint(value) => write_varint(*value, &mut out),
            Payload::Fixed64(raw) => out.extend_from_slice(raw),
            Payload::Fixed32(raw) => out.extend_from_slice(raw),
            Payload::Length(content) => {
                let body = match content {
                    Content::Text(text) => text.as_bytes().to_vec(),
                    Content::Message(inner) => encode_fields(inner),
                    Content::Bytes(raw) => raw.clone(),
                };
                write_varint(body.len() as u64, &mut out);
                out.extend_from_slice(&body);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Shaped like claude.ai's PerformAction: ids and the message text, nested one level down.
    fn chat_message(text: &str) -> Vec<u8> {
        let mut inner = vec![0x0a, 0x04];
        inner.extend_from_slice(b"abcd");
        inner.push(0x1a);
        write_varint(text.len() as u64, &mut inner);
        inner.extend_from_slice(text.as_bytes());
        inner.extend_from_slice(&[0x90, 0x01, 0x01]);
        let mut body = vec![0x12];
        write_varint(inner.len() as u64, &mut body);
        body.extend_from_slice(&inner);
        body
    }

    fn frame(flags: u8, message: &[u8]) -> Vec<u8> {
        let mut framed = vec![flags];
        framed.extend_from_slice(&(message.len() as u32).to_be_bytes());
        framed.extend_from_slice(message);
        framed
    }

    #[test]
    fn unchanged_message_re_encodes_to_the_same_bytes() {
        let bytes = chat_message("hello 123-45-6789 test");
        assert_eq!(
            Protobuf::decode(&bytes, false).unwrap().encode().unwrap(),
            bytes
        );
    }

    #[test]
    fn exposes_the_text_for_scanning() {
        let decoded = Protobuf::decode(&chat_message("hello 123-45-6789 test"), false).unwrap();
        assert_eq!(
            decoded.texts(),
            json!([[["abcd", "hello 123-45-6789 test", null]]])
        );
    }

    #[test]
    fn redacting_a_longer_or_shorter_text_fixes_every_length_prefix() {
        let mut decoded = Protobuf::decode(&chat_message("hello 123-45-6789 test"), false).unwrap();
        decoded.set_texts(&json!([[["abcd", "hello [REDACTED:ssn] test", null]]]));
        let rewritten = decoded.encode().unwrap();
        assert_eq!(rewritten, chat_message("hello [REDACTED:ssn] test"));
        let reread = Protobuf::decode(&rewritten, false).unwrap();
        assert_eq!(
            reread.texts(),
            json!([[["abcd", "hello [REDACTED:ssn] test", null]]])
        );
    }

    #[test]
    fn framed_bodies_keep_their_frame_headers() {
        let framed = frame(0, &chat_message("hi"));
        assert_eq!(
            Protobuf::decode(&framed, true).unwrap().encode().unwrap(),
            framed
        );
    }

    #[test]
    fn rejects_what_it_cannot_read() {
        assert_eq!(
            Protobuf::decode(&[0x12, 0x7f, 0x01], false).err(),
            Some(ProtobufError::Malformed)
        );
        assert_eq!(
            Protobuf::decode(&[0x01, 0x00, 0x00, 0x00, 0x01, 0x00], true).err(),
            Some(ProtobufError::CompressedFrame)
        );
        assert_eq!(
            Protobuf::decode(&[0x00, 0xff, 0xff, 0xff, 0xff], true).err(),
            Some(ProtobufError::FrameTooLarge)
        );
        assert_eq!(
            Protobuf::decode(&[0x00, 0x00], true).err(),
            Some(ProtobufError::Malformed)
        );
    }

    #[test]
    fn field_number_zero_and_unknown_wire_types_are_malformed() {
        assert!(Protobuf::decode(&[0x00, 0x01], false).is_err());
        assert!(Protobuf::decode(&[0x0b, 0x01], false).is_err());
    }

    #[test]
    fn deeply_nested_input_is_handled_without_overflowing_the_stack() {
        let mut nested = vec![0x08, 0x00];
        for _ in 0..2_000 {
            let mut wrapper = vec![0x0a];
            write_varint(nested.len() as u64, &mut wrapper);
            wrapper.extend_from_slice(&nested);
            nested = wrapper;
        }
        let decoded = Protobuf::decode(&nested, false).unwrap();
        assert_eq!(decoded.encode().unwrap(), nested);
    }

    #[test]
    fn non_text_fields_survive_a_round_trip_untouched() {
        let mut bytes = vec![0x08, 0x96, 0x01];
        bytes.extend_from_slice(&[0x11, 1, 2, 3, 4, 5, 6, 7, 8]);
        bytes.extend_from_slice(&[0x1d, 9, 8, 7, 6]);
        bytes.extend_from_slice(&[0x22, 0x02, 0x00, 0xff]);
        assert_eq!(
            Protobuf::decode(&bytes, false).unwrap().encode().unwrap(),
            bytes
        );
    }
}
