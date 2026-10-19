//! Scan throughput on synthetic chat requests. The corpus is generated from a fixed seed and contains only invented
//! values (documentation-range emails, well-known test card numbers, an SSN-shaped number), never real data.
//! Run with `cargo bench -p engine`.
#![allow(clippy::expect_used)]
use contract::Snapshot;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use engine::Scanner;
use serde_json::{json, Value};

const SEED: u64 = 0x5eed_1234_abcd_ef01;
const MESSAGE_BYTES: usize = 1_600;
const SMALL_BODY_BYTES: usize = 64 * 1024;
const LARGE_BODY_BYTES: usize = 1024 * 1024;
/// One message in this many contains synthetic PII.
const PII_EVERY_NTH_MESSAGE: usize = 10;
const WORDS: [&str; 16] = [
    "the", "quick", "brown", "fox", "reviews", "order", "for", "customer", "on", "a", "lazy",
    "dog", "while", "ticket", "refund", "shipment",
];
const SYNTHETIC_PII: [&str; 4] = [
    "ssn 123-45-6789",
    "card 4111 1111 1111 1111",
    "mail jane.doe@example.com",
    "iban GB82WEST12345698765432",
];

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}

fn message_text(random: &mut Lcg, with_pii: bool) -> String {
    let mut text = String::with_capacity(MESSAGE_BYTES + 32);
    while text.len() < MESSAGE_BYTES {
        text.push_str(WORDS[random.below(WORDS.len())]);
        text.push(' ');
        if random.below(12) == 0 {
            text.push_str(&random.below(100_000).to_string());
            text.push(' ');
        }
    }
    if with_pii {
        text.push_str(SYNTHETIC_PII[random.below(SYNTHETIC_PII.len())]);
    }
    text
}

/// A chat request of roughly `target_bytes`, shaped like an API call.
fn request_body(target_bytes: usize) -> Value {
    let mut random = Lcg(SEED);
    let message_count = target_bytes / MESSAGE_BYTES;
    let messages: Vec<Value> = (0..message_count)
        .map(|index| {
            let with_pii = index % PII_EVERY_NTH_MESSAGE == PII_EVERY_NTH_MESSAGE - 1;
            json!({"role": "user", "content": message_text(&mut random, with_pii)})
        })
        .collect();
    json!({"model": "synthetic", "messages": messages})
}

fn scanner() -> Scanner {
    let snapshot: Snapshot = serde_json::from_str(include_str!("../../../examples/rules.json"))
        .expect("the example catalog parses");
    Scanner::from_rules(&snapshot.pii, &[]).expect("the example rules compile")
}

fn bench_scan(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("scan");
    for (name, size) in [("64KiB", SMALL_BODY_BYTES), ("1MiB", LARGE_BODY_BYTES)] {
        let body = request_body(size);
        let bytes = body.to_string().len() as u64;
        group.throughput(Throughput::Bytes(bytes));
        group.bench_function(format!("cold/{name}"), |bench| {
            bench.iter_batched(
                scanner,
                |scanner| scanner.scan(&body),
                BatchSize::LargeInput,
            );
        });
        let warm = scanner();
        warm.scan(&body);
        group.bench_function(format!("repeated/{name}"), |bench| {
            bench.iter(|| warm.scan(&body));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_scan);
criterion_main!(benches);
