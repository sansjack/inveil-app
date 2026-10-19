#![no_main]
use engine::decode;
use libfuzzer_sys::fuzz_target;

const MAX_DECODED_BYTES: usize = 1 << 20;
const ENCODINGS: [Option<&[u8]>; 4] = [None, Some(b"gzip"), Some(b"zstd"), Some(b"identity")];

fuzz_target!(|data: &[u8]| {
    for encoding in ENCODINGS {
        if let Ok(decoded) = decode(encoding, data, MAX_DECODED_BYTES) {
            assert!(decoded.len() <= MAX_DECODED_BYTES);
        }
    }
});
