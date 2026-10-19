#![no_main]
use bytes::BytesMut;
use engine::connect::{cut, Cut};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut buffer = BytesMut::from(data);
    while let Cut::Frame(frame) = cut(&mut buffer) {
        assert_eq!(frame.raw.len(), engine::connect::FRAME_HEADER_LEN + frame.message.len());
    }
});
