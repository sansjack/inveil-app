//! Reads real token counts out of a response as it streams past, so usage events carry them without buffering
//! the response or delaying the client.
use super::signals::ResponseReader;
use crate::backend::UsageReporter;
use axum::http::header::CONTENT_ENCODING;
use axum::http::HeaderMap;
use brotli_decompressor::DecompressorWriter;
use contract::UsageEvent;
use flate2::write::{GzDecoder, ZlibDecoder};
use serde_json::Value;
use std::io::{self, Write};
use std::sync::Arc;
use std::time::Instant;
use zstd::stream::write::Decoder as ZstdDecoder;
use zstd::zstd_safe::DParameter;

const MAX_JSON_BODY_BYTES: usize = 1 << 20;
const MAX_SSE_LINE_BYTES: usize = 1 << 20;
/// How much a compressed response may expand before we stop decoding it. A chat reply is a few hundred KiB at
/// most, so 32 MiB leaves room for very long streams while a zip bomb costs at most a few tens of milliseconds.
/// Whatever was counted before the budget ran out is still reported.
const MAX_DECODED_BYTES: usize = 32 << 20;
const BROTLI_BUFFER_BYTES: usize = 4096;
/// Caps the window a zstd frame may ask us to allocate (2^23 = 8 MiB; the format's default limit is 128 MiB).
const ZSTD_WINDOW_LOG_MAX: u32 = 23;

/// Token counts for one response. `input_tokens` is the whole prompt; the cache counts are subsets of it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
}

/// How the upstream compressed the response, from its `Content-Encoding` header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Identity,
    Gzip,
    /// The zlib format, which is what HTTP means by `deflate`. Raw deflate streams are not recognised.
    Deflate,
    Brotli,
    Zstd,
    /// Anything else, including stacked encodings such as `gzip, br`. Counting is skipped.
    Unsupported,
}

impl Encoding {
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let mut values = headers.get_all(CONTENT_ENCODING).iter();
        let Some(value) = values.next() else {
            return Self::Identity;
        };
        if values.next().is_some() {
            return Self::Unsupported;
        }
        let Ok(name) = value.to_str() else {
            return Self::Unsupported;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "" | "identity" => Self::Identity,
            "gzip" | "x-gzip" => Self::Gzip,
            "deflate" => Self::Deflate,
            "br" => Self::Brotli,
            "zstd" => Self::Zstd,
            _ => Self::Unsupported,
        }
    }
}

fn count(value: Option<&Value>) -> u64 {
    value.and_then(Value::as_u64).unwrap_or(0)
}

/// Reads token counts out of plain (already decoded) response bytes. As a `Write` it is the sink a decoder
/// writes into, and refuses bytes once the decoded-size budget is used up.
struct Parser {
    is_sse: bool,
    pending: Vec<u8>,
    totals: Totals,
    reader: ResponseReader,
    remaining_budget: Option<usize>,
}

impl Parser {
    fn new(is_sse: bool, remaining_budget: Option<usize>, reader: ResponseReader) -> Self {
        Self {
            is_sse,
            pending: Vec::new(),
            totals: Totals::default(),
            reader,
            remaining_budget,
        }
    }

    fn observe(&mut self, chunk: &[u8]) {
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
        // Comment lines (`: OPENROUTER PROCESSING`) and `event:` lines carry no data.
        let Some(data) = text.trim().strip_prefix("data:") else {
            return;
        };
        if !data.contains("\"usage") && !self.reader.wants_body() {
            return;
        }
        if let Ok(value) = serde_json::from_str::<Value>(data.trim()) {
            self.reader.observe(&value);
            self.add(&value);
        }
    }

    fn add(&mut self, value: &Value) {
        let gemini = value
            .get("usageMetadata")
            .or_else(|| value.pointer("/response/usageMetadata"));
        if let Some(metadata) = gemini {
            self.add_gemini(metadata);
            return;
        }
        let Some(usage) = value
            .get("usage")
            .or_else(|| value.pointer("/message/usage"))
            .or_else(|| value.pointer("/response/usage"))
        else {
            return;
        };
        // Anthropic reports cache tokens beside `input_tokens`, so they are added to make the whole prompt.
        // OpenAI includes cached tokens in the prompt already and reports the subset under
        // `input_tokens_details` (Responses) or `prompt_tokens_details` (Chat Completions). The Chat Completions
        // names `prompt_tokens` and `completion_tokens` mean the same as `input_tokens` and `output_tokens`.
        // Reasoning tokens are already inside the output count, so they are not added again.
        // ponytail: Anthropic's 5-minute and 1-hour cache writes (`cache_creation.ephemeral_*_input_tokens`) are not
        // split because OpenRouter publishes a single cache-write rate.
        let cache_read = count(usage.get("cache_read_input_tokens"))
            + count(usage.pointer("/input_tokens_details/cached_tokens"))
            + count(usage.pointer("/prompt_tokens_details/cached_tokens"));
        let cache_write = count(usage.get("cache_creation_input_tokens"));
        let input = count(usage.get("input_tokens"))
            + count(usage.get("prompt_tokens"))
            + count(usage.get("cache_read_input_tokens"))
            + cache_write;
        let output = count(usage.get("output_tokens")) + count(usage.get("completion_tokens"));
        self.raise_totals(input, output, cache_read, cache_write);
    }

    /// Gemini's `promptTokenCount` already includes `cachedContentTokenCount`. Thinking tokens are billed as
    /// output but reported apart from `candidatesTokenCount`, so they are added to it. `toolUsePromptTokenCount`
    /// is ignored because Google's docs do not say how it is billed.
    fn add_gemini(&mut self, metadata: &Value) {
        let output =
            count(metadata.get("candidatesTokenCount")) + count(metadata.get("thoughtsTokenCount"));
        self.raise_totals(
            count(metadata.get("promptTokenCount")),
            output,
            count(metadata.get("cachedContentTokenCount")),
            0,
        );
    }

    /// Streamed usage is cumulative, so the largest value seen is the final one.
    fn raise_totals(&mut self, input: u64, output: u64, cache_read: u64, cache_write: u64) {
        let totals = &mut self.totals;
        totals.input_tokens = totals.input_tokens.max(input);
        totals.output_tokens = totals.output_tokens.max(output);
        totals.cache_read_tokens = totals.cache_read_tokens.max(cache_read);
        totals.cache_write_tokens = totals.cache_write_tokens.max(cache_write);
    }

    fn totals(&mut self) -> Totals {
        if !self.is_sse {
            if let Ok(value) = serde_json::from_slice::<Value>(&self.pending) {
                self.reader.observe(&value);
                self.add(&value);
            }
            self.pending.clear();
        }
        self.totals
    }
}

impl Write for Parser {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let allowed = self
            .remaining_budget
            .map_or(bytes.len(), |remaining| bytes.len().min(remaining));
        self.observe(&bytes[..allowed]);
        if let Some(remaining) = &mut self.remaining_budget {
            *remaining -= allowed;
        }
        if allowed < bytes.len() {
            return Err(io::Error::other("decoded size budget used up"));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Decodes a copy of the response bytes as they arrive. The bytes sent to the caller are never touched.
enum Source {
    Plain(Parser),
    Gzip(GzDecoder<Parser>),
    Deflate(ZlibDecoder<Parser>),
    Brotli(Box<DecompressorWriter<Parser>>),
    Zstd(Box<ZstdDecoder<'static, Parser>>),
}

/// Counts tokens in a response from any supported provider, either an SSE stream or one JSON body, compressed or not.
pub struct UsageCounter {
    source: Source,
    /// Set when decoding failed (corrupt or truncated data, budget used up) or the encoding is unsupported.
    stopped: bool,
}

impl UsageCounter {
    #[cfg(test)]
    pub fn new(is_sse: bool) -> Self {
        Self::encoded(is_sse, Encoding::Identity, ResponseReader::default())
    }

    pub fn encoded(is_sse: bool, encoding: Encoding, reader: ResponseReader) -> Self {
        let budget = (encoding != Encoding::Identity).then_some(MAX_DECODED_BYTES);
        let parser = |reader| Parser::new(is_sse, budget, reader);
        let (source, stopped) = match encoding {
            Encoding::Identity => (Source::Plain(parser(reader)), false),
            Encoding::Gzip => (Source::Gzip(GzDecoder::new(parser(reader))), false),
            Encoding::Deflate => (Source::Deflate(ZlibDecoder::new(parser(reader))), false),
            Encoding::Brotli => {
                let decoder = DecompressorWriter::new(parser(reader), BROTLI_BUFFER_BYTES);
                (Source::Brotli(Box::new(decoder)), false)
            }
            // The decoder owns the parser, so a failure to start it would lose the reader. It starts with an
            // empty one and takes the real one once it exists.
            Encoding::Zstd => match zstd_decoder(parser(ResponseReader::default())) {
                Ok(mut decoder) => {
                    decoder.get_mut().reader = reader;
                    (Source::Zstd(Box::new(decoder)), false)
                }
                Err(error) => {
                    tracing::debug!(%error, "could not start the zstd decoder");
                    (Source::Plain(parser(reader)), true)
                }
            },
            Encoding::Unsupported => (Source::Plain(parser(reader)), true),
        };
        Self { source, stopped }
    }

    pub fn observe(&mut self, chunk: &[u8]) {
        if self.stopped {
            return;
        }
        let result = match &mut self.source {
            Source::Plain(parser) => {
                parser.observe(chunk);
                Ok(())
            }
            Source::Gzip(decoder) => decoder.write_all(chunk),
            Source::Deflate(decoder) => decoder.write_all(chunk),
            Source::Brotli(decoder) => decoder.write_all(chunk),
            Source::Zstd(decoder) => decoder.write_all(chunk),
        };
        self.stop_on_error(result);
    }

    /// Pushes whatever the decoder still holds to the parser, then returns the totals.
    pub fn totals(&mut self) -> Totals {
        if !self.stopped {
            let result = match &mut self.source {
                Source::Plain(_) => Ok(()),
                Source::Gzip(decoder) => decoder.flush(),
                Source::Deflate(decoder) => decoder.flush(),
                Source::Brotli(decoder) => decoder.flush(),
                Source::Zstd(decoder) => decoder.flush(),
            };
            self.stop_on_error(result);
        }
        self.parser().totals()
    }

    pub fn stamp(&mut self, event: &mut UsageEvent) {
        self.parser().reader.stamp(event);
    }

    fn stop_on_error(&mut self, result: io::Result<()>) {
        let Err(error) = result else {
            return;
        };
        self.stopped = true;
        tracing::debug!(%error, "stopped decoding the response; reporting what was counted");
    }

    fn parser(&mut self) -> &mut Parser {
        match &mut self.source {
            Source::Plain(parser) => parser,
            Source::Gzip(decoder) => decoder.get_mut(),
            Source::Deflate(decoder) => decoder.get_mut(),
            Source::Brotli(decoder) => decoder.get_mut(),
            Source::Zstd(decoder) => decoder.get_mut(),
        }
    }
}

fn zstd_decoder(parser: Parser) -> io::Result<ZstdDecoder<'static, Parser>> {
    let mut decoder = ZstdDecoder::new(parser)?;
    decoder.set_parameter(DParameter::WindowLogMax(ZSTD_WINDOW_LOG_MAX))?;
    Ok(decoder)
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
    pub fn new(
        reporter: Arc<UsageReporter>,
        event: UsageEvent,
        is_sse: bool,
        encoding: Encoding,
        reader: ResponseReader,
    ) -> Self {
        Self {
            reporter,
            event,
            started: Instant::now(),
            counter: UsageCounter::encoded(is_sse, encoding, reader),
        }
    }

    pub fn observe(&mut self, chunk: &[u8]) {
        self.counter.observe(chunk);
    }
}

impl Drop for Tap {
    fn drop(&mut self) {
        let totals = self.counter.totals();
        self.event.input_tokens = totals.input_tokens;
        self.event.output_tokens = totals.output_tokens;
        self.event.cache_read_tokens = totals.cache_read_tokens;
        self.event.cache_write_tokens = totals.cache_write_tokens;
        self.counter.stamp(&mut self.event);
        self.event.latency_ms =
            u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        tracing::debug!(
            latency_ms = self.event.latency_ms,
            input_tokens = totals.input_tokens,
            output_tokens = totals.output_tokens,
            "response finished"
        );
        self.reporter.report(self.event.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::signals::{Evidence, Signals};
    use axum::http::HeaderMap;
    use contract::Billing;

    const STREAM: &str = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"cache_read_input_tokens\":90,\"output_tokens\":1}}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hi\"}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":42}}\n\n";

    fn totals(input: u64, output: u64, read: u64, write: u64) -> Totals {
        Totals {
            input_tokens: input,
            output_tokens: output,
            cache_read_tokens: read,
            cache_write_tokens: write,
        }
    }

    #[test]
    fn counts_streamed_usage_even_when_chunks_split_mid_line() {
        let mut counter = UsageCounter::new(true);
        for chunk in STREAM.as_bytes().chunks(7) {
            counter.observe(chunk);
        }
        assert_eq!(counter.totals(), totals(100, 42, 90, 0));
    }

    #[test]
    fn anthropic_streaming_adds_cache_tokens_to_the_prompt_and_reports_them_separately() {
        let stream = "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"cache_creation_input_tokens\":30,\"cache_read_input_tokens\":60,\"output_tokens\":1}}}\n\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":9}}\n\n";
        let mut counter = UsageCounter::new(true);
        counter.observe(stream.as_bytes());
        assert_eq!(counter.totals(), totals(100, 9, 60, 30));
    }

    #[test]
    fn anthropic_json_response_reports_cache_tokens() {
        let mut counter = UsageCounter::new(false);
        counter.observe(br#"{"usage":{"input_tokens":4,"cache_creation_input_tokens":6,"cache_read_input_tokens":20,"output_tokens":7}}"#);
        assert_eq!(counter.totals(), totals(30, 7, 20, 6));
    }

    #[test]
    fn openai_cached_tokens_are_a_subset_of_input_tokens() {
        let mut counter = UsageCounter::new(false);
        counter.observe(br#"{"usage":{"input_tokens":100,"input_tokens_details":{"cached_tokens":80},"output_tokens":5}}"#);
        assert_eq!(counter.totals(), totals(100, 5, 80, 0));
    }

    #[test]
    fn openai_streaming_reads_cached_tokens_from_the_completed_event() {
        let stream = "data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":50,\"input_tokens_details\":{\"cached_tokens\":40},\"output_tokens\":3}}}\n\n";
        let mut counter = UsageCounter::new(true);
        counter.observe(stream.as_bytes());
        assert_eq!(counter.totals(), totals(50, 3, 40, 0));
    }

    #[test]
    fn each_counter_keeps_its_largest_streamed_value() {
        let stream = "data: {\"usage\":{\"input_tokens\":5,\"cache_read_input_tokens\":50,\"cache_creation_input_tokens\":5,\"output_tokens\":10}}\n\ndata: {\"usage\":{\"input_tokens\":2,\"output_tokens\":20}}\n\n";
        let mut counter = UsageCounter::new(true);
        counter.observe(stream.as_bytes());
        assert_eq!(counter.totals(), totals(60, 20, 50, 5));
    }

    #[test]
    fn counts_usage_from_a_plain_json_response() {
        let mut counter = UsageCounter::new(false);
        counter.observe(br#"{"usage":{"input_tokens":5,"output_tokens":6}}"#);
        assert_eq!(counter.totals(), totals(5, 6, 0, 0));
    }

    #[test]
    fn a_response_signal_reads_the_model_from_a_stream_that_has_no_usage_yet() {
        let signals = Signals::builtin().unwrap();
        let reader = signals.response_reader(
            "openrouter.ai",
            "/api/v1/chat/completions",
            &Evidence::default(),
            &HeaderMap::new(),
        );
        let mut counter = UsageCounter::encoded(true, Encoding::Identity, reader);
        counter.observe(b"data: {\"model\":\"openai/gpt-4\",\"choices\":[]}\n\n");
        counter.observe(b"data: {\"usage\":{\"input_tokens\":5,\"output_tokens\":6}}\n\n");
        assert_eq!(counter.totals(), totals(5, 6, 0, 0));
        let mut event = crate::backend::new_event("openrouter.ai", "", 200, false, 0, Billing::Api);
        counter.stamp(&mut event);
        assert_eq!(event.model, "openai/gpt-4");
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn counted(encoding: Encoding, is_sse: bool, compressed: &[u8]) -> Totals {
        let mut counter = UsageCounter::encoded(is_sse, encoding, ResponseReader::default());
        for chunk in compressed.chunks(5) {
            counter.observe(chunk);
        }
        counter.totals()
    }

    #[test]
    fn counts_gemini_usage_with_thinking_added_to_the_output_and_cached_tokens_inside_the_prompt() {
        let mut counter = UsageCounter::new(false);
        counter.observe(br#"{"usageMetadata":{"promptTokenCount":1200,"cachedContentTokenCount":1000,"candidatesTokenCount":20,"thoughtsTokenCount":150,"toolUsePromptTokenCount":7,"totalTokenCount":1377}}"#);
        assert_eq!(counter.totals(), totals(1200, 170, 1000, 0));
    }

    #[test]
    fn counts_gemini_code_assist_usage_wrapped_in_a_response_object() {
        let stream = "data: {\"response\":{\"usageMetadata\":{\"promptTokenCount\":8,\"candidatesTokenCount\":2}},\"traceId\":\"t\"}\n\n";
        let mut counter = UsageCounter::new(true);
        counter.observe(stream.as_bytes());
        assert_eq!(counter.totals(), totals(8, 2, 0, 0));
    }

    #[test]
    fn chat_completions_reasoning_tokens_are_not_added_to_the_completion_tokens_again() {
        let mut counter = UsageCounter::new(false);
        counter.observe(br#"{"usage":{"prompt_tokens":100,"completion_tokens":40,"prompt_tokens_details":{"cached_tokens":64},"completion_tokens_details":{"reasoning_tokens":30}}}"#);
        assert_eq!(counter.totals(), totals(100, 40, 64, 0));
    }

    #[test]
    fn chat_completions_stream_ignores_null_usage_and_comment_lines() {
        let stream = ": OPENROUTER PROCESSING\n\ndata: {\"choices\":[],\"usage\":null}\n\ndata: {\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":2}}\n\ndata: [DONE]\n\n";
        let mut counter = UsageCounter::new(true);
        counter.observe(stream.as_bytes());
        assert_eq!(counter.totals(), totals(9, 2, 0, 0));
    }

    #[test]
    fn decodes_every_supported_encoding() {
        let body = br#"{"usage":{"input_tokens":5,"output_tokens":6}}"#;
        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        zlib.write_all(body).unwrap();
        let mut brotli = brotli::CompressorWriter::new(Vec::new(), 4096, 5, 22);
        brotli.write_all(body).unwrap();
        let zstd = zstd::stream::encode_all(body.as_slice(), 3).unwrap();
        for (encoding, compressed) in [
            (Encoding::Gzip, gzip(body)),
            (Encoding::Deflate, zlib.finish().unwrap()),
            (Encoding::Brotli, brotli.into_inner()),
            (Encoding::Zstd, zstd),
        ] {
            assert_eq!(
                counted(encoding, false, &compressed),
                totals(5, 6, 0, 0),
                "{encoding:?}"
            );
        }
    }

    #[test]
    fn reads_the_encoding_from_the_content_encoding_header() {
        let encoding = |value: Option<&str>| {
            let mut headers = HeaderMap::new();
            if let Some(value) = value {
                headers.insert(CONTENT_ENCODING, value.parse().unwrap());
            }
            Encoding::from_headers(&headers)
        };
        assert_eq!(encoding(None), Encoding::Identity);
        assert_eq!(encoding(Some("identity")), Encoding::Identity);
        assert_eq!(encoding(Some("GZip")), Encoding::Gzip);
        assert_eq!(encoding(Some("br")), Encoding::Brotli);
        assert_eq!(encoding(Some("gzip, br")), Encoding::Unsupported);
        assert_eq!(encoding(Some("compress")), Encoding::Unsupported);
    }

    #[test]
    fn a_corrupt_compressed_body_counts_nothing_and_does_not_panic() {
        for encoding in [
            Encoding::Gzip,
            Encoding::Deflate,
            Encoding::Brotli,
            Encoding::Zstd,
            Encoding::Unsupported,
        ] {
            assert_eq!(
                counted(encoding, false, b"this is not compressed data at all"),
                Totals::default(),
                "{encoding:?}"
            );
        }
    }

    #[test]
    fn a_truncated_stream_keeps_what_was_decoded_before_the_cut() {
        let stream = format!("{STREAM}data: {{\"usage\":{{\"output_tokens\":99}}}}\n\n");
        let compressed = gzip(stream.as_bytes());
        let cut = &compressed[..compressed.len() - 12];
        assert_eq!(counted(Encoding::Gzip, true, cut).input_tokens, 100);
    }

    #[test]
    fn decoding_stops_at_the_budget_and_keeps_what_was_counted_before_it() {
        let usage = "data: {\"usage\":{\"input_tokens\":5,\"output_tokens\":6}}\n\n";
        let padding = "\n".repeat(MAX_DECODED_BYTES + 1);
        let usage_first = gzip(format!("{usage}{padding}{usage}").as_bytes());
        assert_eq!(
            counted(Encoding::Gzip, true, &usage_first),
            totals(5, 6, 0, 0)
        );

        let usage_last = gzip(format!("{padding}{usage}").as_bytes());
        assert_eq!(
            counted(Encoding::Gzip, true, &usage_last),
            Totals::default()
        );
    }

    #[test]
    fn missing_usage_counts_as_zero() {
        let mut counter = UsageCounter::new(true);
        counter.observe(b"data: {\"type\":\"ping\"}\n\n");
        assert_eq!(counter.totals(), Totals::default());
    }
}
