#![no_main]
use engine::protobuf::Protobuf;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for framed in [false, true] {
        let Ok(mut message) = Protobuf::decode(data, framed) else {
            continue;
        };
        let texts = message.texts();
        message.set_texts(&texts);
        let Ok(encoded) = message.encode() else {
            continue;
        };
        let reparsed = Protobuf::decode(&encoded, framed);
        assert!(reparsed.is_ok(), "re-encoded protobuf must parse");
        assert_eq!(reparsed.map(|message| message.texts()), Ok(texts));
    }
});
