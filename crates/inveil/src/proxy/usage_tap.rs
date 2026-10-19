//! Reads real token counts out of a response as it streams past, so usage events carry them without buffering
//! the response or delaying the client.
use crate::backend::UsageReporter;
use contract::UsageEvent;
use serde_json::Value;
use std::sync::Arc;
use std::time::Instant;

const MAX_JSON_BODY_BYTES: usize = 1 << 20;
const MAX_SSE_LINE_BYTES: usize = 1 << 20;
const INPUT_TOKEN_KEYS: [&str; 3] = [
    "input_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
];

/// Counts tokens in an Anthropic- or OpenAI-style response, either an SSE stream or one JSON body.
pub struct UsageCounter {
    is_sse: bool,
    pending: Vec<u8>,
    input_tokens: u64,
    output_tokens: u64,
}

impl UsageCounter {
    pub fn new(is_sse: bool) -> Self {
        Self {
            is_sse,
            pending: Vec::new(),
            input_tokens: 0,
            output_tokens: 0,
        }
    }

    pub fn observe(&mut self, chunk: &[u8]) {
        if !self.is_sse {
            if self.pending.len() < MAX_JSON_BODY_BYTES {
                self.pending.extend_from_slice(chunk);
            }
            return;
        }
        self.pending.extend_from_slice(chunk);
        while let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=end).collect();
            self.read_sse_line(&line);
        }
        if self.pending.len() > MAX_SSE_LINE_BYTES {
            self.pending.clear();
        }
    }

    fn read_sse_line(&mut self, line: &[u8]) {
        let Ok(text) = std::str::from_utf8(line) else {
            return;
        };
        let Some(data) = text.trim().strip_prefix("data:") else {
            return;
        };
        if !data.contains("\"usage\"") {
            return;
        }
        if let Ok(value) = serde_json::from_str::<Value>(data.trim()) {
            self.add(&value);
        }
    }

    fn add(&mut self, value: &Value) {
        let Some(usage) = value
            .get("usage")
            .or_else(|| value.pointer("/message/usage"))
            .or_else(|| value.pointer("/response/usage"))
        else {
            return;
        };
        let input: u64 = INPUT_TOKEN_KEYS
            .iter()
            .filter_map(|key| usage.get(*key)?.as_u64())
            .sum();
        let output = usage
            .get("output_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        // Streamed usage is cumulative, so the largest value seen is the final one.
        self.input_tokens = self.input_tokens.max(input);
        self.output_tokens = self.output_tokens.max(output);
    }

    pub fn totals(&mut self) -> (u64, u64) {
        if !self.is_sse {
            if let Ok(value) = serde_json::from_slice::<Value>(&self.pending) {
                self.add(&value);
            }
            self.pending.clear();
        }
        (self.input_tokens, self.output_tokens)
    }
}

/// Wraps a response body: counts tokens as it streams and reports the event when the body ends or the client hangs
/// up (drop), whichever comes first.
pub struct Tap {
    reporter: Arc<UsageReporter>,
    event: UsageEvent,
    started: Instant,
    counter: UsageCounter,
}

impl Tap {
    pub fn new(reporter: Arc<UsageReporter>, event: UsageEvent, is_sse: bool) -> Self {
        Self {
            reporter,
            event,
            started: Instant::now(),
            counter: UsageCounter::new(is_sse),
        }
    }

    pub fn observe(&mut self, chunk: &[u8]) {
        self.counter.observe(chunk);
    }
}

impl Drop for Tap {
    fn drop(&mut self) {
        let (input_tokens, output_tokens) = self.counter.totals();
        self.event.input_tokens = input_tokens;
        self.event.output_tokens = output_tokens;
        self.event.latency_ms =
            u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        tracing::debug!(
            latency_ms = self.event.latency_ms,
            input_tokens,
            output_tokens,
            "response finished"
        );
        self.reporter.report(self.event.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STREAM: &str = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"cache_read_input_tokens\":90,\"output_tokens\":1}}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hi\"}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":42}}\n\n";

    #[test]
    fn counts_streamed_usage_even_when_chunks_split_mid_line() {
        let mut counter = UsageCounter::new(true);
        for chunk in STREAM.as_bytes().chunks(7) {
            counter.observe(chunk);
        }
        assert_eq!(counter.totals(), (100, 42));
    }

    #[test]
    fn counts_usage_from_a_plain_json_response() {
        let mut counter = UsageCounter::new(false);
        counter.observe(br#"{"usage":{"input_tokens":5,"output_tokens":6}}"#);
        assert_eq!(counter.totals(), (5, 6));
    }

    #[test]
    fn missing_usage_counts_as_zero() {
        let mut counter = UsageCounter::new(true);
        counter.observe(b"data: {\"type\":\"ping\"}\n\n");
        assert_eq!(counter.totals(), (0, 0));
    }
}
