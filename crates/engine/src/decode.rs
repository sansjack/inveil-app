//! Undoing `Content-Encoding`. A body that cannot be fully decoded within the size cap is an error, never a truncated
//! success, so an oversized or corrupt body can only be blocked and not smuggled past the scanner.
use std::borrow::Cow;
use std::io::Read;

const MIB: usize = 1 << 20;
/// Default cap on a decoded body; a few KiB of compressed text must not expand into gigabytes.
pub const DEFAULT_MAX_DECODED_BYTES: usize = 64 * MIB;
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("unreadable Content-Encoding header")]
    UnreadableEncodingHeader,
    #[error("unsupported Content-Encoding '{0}'")]
    UnsupportedEncoding(String),
    #[error("corrupt {0} body")]
    Corrupt(&'static str),
    #[error("the decoded body is larger than {limit} bytes")]
    TooLarge { limit: usize },
    #[error("unrecognised compression")]
    UnrecognisedCompression,
}

#[derive(Clone, Copy)]
enum Compression {
    Gzip,
    Zstd,
}

impl Compression {
    fn name(self) -> &'static str {
        match self {
            Compression::Gzip => "gzip",
            Compression::Zstd => "zstd",
        }
    }

    fn detect(bytes: &[u8]) -> Option<Self> {
        if bytes.starts_with(&GZIP_MAGIC) {
            return Some(Compression::Gzip);
        }
        bytes.starts_with(&ZSTD_MAGIC).then_some(Compression::Zstd)
    }
}

fn inflate(
    compression: Compression,
    raw: &[u8],
    max_decoded_bytes: usize,
) -> Result<Vec<u8>, DecodeError> {
    let corrupt = |_| DecodeError::Corrupt(compression.name());
    let read_limit = u64::try_from(max_decoded_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut decoded = Vec::new();
    match compression {
        Compression::Gzip => flate2::read::GzDecoder::new(raw)
            .take(read_limit)
            .read_to_end(&mut decoded)
            .map_err(corrupt)?,
        Compression::Zstd => zstd::stream::read::Decoder::new(raw)
            .map_err(corrupt)?
            .take(read_limit)
            .read_to_end(&mut decoded)
            .map_err(corrupt)?,
    };
    if decoded.len() > max_decoded_bytes {
        return Err(DecodeError::TooLarge {
            limit: max_decoded_bytes,
        });
    }
    Ok(decoded)
}

/// Decodes a body given the raw `Content-Encoding` header value (`None` when the header is absent).
pub fn decode<'a>(
    content_encoding: Option<&[u8]>,
    raw: &'a [u8],
    max_decoded_bytes: usize,
) -> Result<Cow<'a, [u8]>, DecodeError> {
    let encoding = match content_encoding {
        None => String::new(),
        Some(bytes) => std::str::from_utf8(bytes)
            .map_err(|_| DecodeError::UnreadableEncodingHeader)?
            .trim()
            .to_ascii_lowercase(),
    };
    let compression = match encoding.as_str() {
        "" | "identity" => {
            if raw.len() > max_decoded_bytes {
                return Err(DecodeError::TooLarge {
                    limit: max_decoded_bytes,
                });
            }
            return Ok(Cow::Borrowed(raw));
        }
        "gzip" => Compression::Gzip,
        "zstd" => Compression::Zstd,
        other => return Err(DecodeError::UnsupportedEncoding(other.to_string())),
    };
    inflate(compression, raw, max_decoded_bytes).map(Cow::Owned)
}

/// Undoes gzip or zstd, recognised by their first bytes. Used for streamed messages, which carry no header.
pub fn decompress_detected(
    message: &[u8],
    max_decoded_bytes: usize,
) -> Result<Vec<u8>, DecodeError> {
    let compression = Compression::detect(message).ok_or(DecodeError::UnrecognisedCompression)?;
    inflate(compression, message, max_decoded_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const LIMIT: usize = 1024;

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn zstd(bytes: &[u8]) -> Vec<u8> {
        zstd::stream::encode_all(bytes, 3).unwrap()
    }

    #[test]
    fn no_header_and_identity_pass_the_body_through() {
        assert_eq!(decode(None, b"abc", LIMIT).unwrap().as_ref(), b"abc");
        assert_eq!(
            decode(Some(b" Identity "), b"abc", LIMIT).unwrap().as_ref(),
            b"abc"
        );
    }

    #[test]
    fn gzip_and_zstd_are_decoded_case_insensitively() {
        assert_eq!(
            decode(Some(b"GZIP"), &gzip(b"hello"), LIMIT)
                .unwrap()
                .as_ref(),
            b"hello"
        );
        assert_eq!(
            decode(Some(b"zstd"), &zstd(b"hello"), LIMIT)
                .unwrap()
                .as_ref(),
            b"hello"
        );
    }

    #[test]
    fn unknown_encodings_and_unreadable_headers_fail_closed() {
        assert_eq!(
            decode(Some(b"br"), b"x", LIMIT),
            Err(DecodeError::UnsupportedEncoding("br".into()))
        );
        assert_eq!(
            decode(Some(&[0xff, 0xfe]), b"x", LIMIT),
            Err(DecodeError::UnreadableEncodingHeader)
        );
    }

    #[test]
    fn corrupt_bodies_are_errors() {
        assert_eq!(
            decode(Some(b"gzip"), b"not gzip", LIMIT),
            Err(DecodeError::Corrupt("gzip"))
        );
        assert_eq!(
            decode(Some(b"zstd"), b"not zstd", LIMIT),
            Err(DecodeError::Corrupt("zstd"))
        );
    }

    #[test]
    fn a_body_that_expands_past_the_cap_is_an_error_not_a_truncation() {
        let bomb = vec![b'a'; LIMIT * 100];
        let expected = Err(DecodeError::TooLarge { limit: LIMIT });
        assert_eq!(decode(Some(b"gzip"), &gzip(&bomb), LIMIT), expected);
        assert_eq!(decode(Some(b"zstd"), &zstd(&bomb), LIMIT), expected);
        assert_eq!(decode(None, &bomb, LIMIT), expected);
    }

    #[test]
    fn a_body_exactly_at_the_cap_is_accepted() {
        let body = vec![b'a'; LIMIT];
        assert_eq!(
            decode(Some(b"gzip"), &gzip(&body), LIMIT).unwrap().len(),
            LIMIT
        );
    }

    #[test]
    fn detected_compression_handles_gzip_and_zstd_only() {
        assert_eq!(
            decompress_detected(&gzip(b"some text"), LIMIT).unwrap(),
            b"some text"
        );
        assert_eq!(
            decompress_detected(&zstd(b"more text"), LIMIT).unwrap(),
            b"more text"
        );
        assert_eq!(
            decompress_detected(b"neither of those", LIMIT),
            Err(DecodeError::UnrecognisedCompression)
        );
        assert_eq!(
            decompress_detected(&[0x1f, 0x8b, 0, 0], LIMIT),
            Err(DecodeError::Corrupt("gzip"))
        );
    }
}
