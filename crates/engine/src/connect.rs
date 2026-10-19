//! The framing of streaming Connect / gRPC-web calls, such as Cursor's agent: a request body that stays open for the
//! whole conversation, made of frames `flags (1 byte) | length (4 bytes, big endian) | message`. Flag bit 0 means the
//! message is compressed. This module only cuts a byte stream into frames and builds frames; what is inside a message
//! is `protobuf`'s business.
use bytes::{Bytes, BytesMut};

pub const FRAME_HEADER_LEN: usize = 5;
/// A frame announcing more than this is not read, and the stream is blocked as unreadable.
pub const MAX_FRAME_BYTES: usize = 64 << 20;
pub const COMPRESSED_FLAG: u8 = 1;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("a frame message of {len} bytes does not fit a frame")]
pub struct FrameTooLarge {
    pub len: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub flags: u8,
    pub message: Bytes,
    /// The frame exactly as it arrived, to forward unchanged when nothing needs to change.
    pub raw: Bytes,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Cut {
    /// A whole frame was available and has been removed from the buffer.
    Frame(Frame),
    /// More bytes are needed.
    Incomplete,
    /// The announced length is larger than [`MAX_FRAME_BYTES`].
    TooLarge,
}

/// Takes the first complete frame out of `buffer`, if there is one.
pub fn cut(buffer: &mut BytesMut) -> Cut {
    if buffer.len() < FRAME_HEADER_LEN {
        return Cut::Incomplete;
    }
    let announced = u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]);
    let Ok(length) = usize::try_from(announced) else {
        return Cut::TooLarge;
    };
    if length > MAX_FRAME_BYTES {
        return Cut::TooLarge;
    }
    if buffer.len() < FRAME_HEADER_LEN + length {
        return Cut::Incomplete;
    }
    let raw = buffer.split_to(FRAME_HEADER_LEN + length).freeze();
    let flags = raw[0];
    Cut::Frame(Frame {
        flags,
        message: raw.slice(FRAME_HEADER_LEN..),
        raw,
    })
}

pub fn encode(flags: u8, message: &[u8]) -> Result<Bytes, FrameTooLarge> {
    let length = u32::try_from(message.len()).map_err(|_| FrameTooLarge { len: message.len() })?;
    let mut frame = BytesMut::with_capacity(FRAME_HEADER_LEN + message.len());
    frame.extend_from_slice(&[flags]);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(message);
    Ok(frame.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(flags: u8, message: &[u8]) -> Bytes {
        encode(flags, message).unwrap()
    }

    #[test]
    fn frames_are_cut_from_a_stream_however_the_bytes_arrive() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&frame(0, b"first"));
        stream.extend_from_slice(&frame(1, b"second"));
        stream.extend_from_slice(&frame(0, b""));

        let mut buffer = BytesMut::new();
        let mut seen = Vec::new();
        for chunk in stream.chunks(3) {
            buffer.extend_from_slice(chunk);
            while let Cut::Frame(frame) = cut(&mut buffer) {
                seen.push((frame.flags, frame.message.to_vec(), frame.raw.len()));
            }
        }
        assert_eq!(
            seen,
            [
                (0, b"first".to_vec(), 10),
                (1, b"second".to_vec(), 11),
                (0, Vec::new(), 5)
            ]
        );
        assert!(buffer.is_empty());
    }

    #[test]
    fn a_partial_frame_waits_and_an_enormous_one_is_refused() {
        let mut buffer = BytesMut::from(&frame(0, b"abcdef")[..8]);
        assert_eq!(cut(&mut buffer), Cut::Incomplete);
        assert_eq!(
            buffer.len(),
            8,
            "nothing is consumed until the frame is whole"
        );

        let mut huge = BytesMut::from(&[0u8, 0xff, 0xff, 0xff, 0xff][..]);
        assert_eq!(cut(&mut huge), Cut::TooLarge);
    }

    #[test]
    fn the_original_frame_bytes_are_kept_for_forwarding_unchanged() {
        let original = frame(0, b"hello");
        let mut buffer = BytesMut::from(&original[..]);
        let Cut::Frame(cut_frame) = cut(&mut buffer) else {
            panic!("expected a frame");
        };
        assert_eq!(cut_frame.raw, original);
    }
}
