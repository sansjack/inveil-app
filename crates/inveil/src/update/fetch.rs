//! Network access for the updater behind a trait, so everything above it is tested without a network. The real
//! implementation speaks https only: redirects must stay on https and every request has a connect and total timeout.
use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use reqwest::Url;
use std::io::Read;
use std::net::IpAddr;
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REDIRECTS: usize = 5;

pub trait Fetcher {
    fn open(&self, url: &str, timeout: Duration) -> Result<Box<dyn Read>, FetchError>;
}

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("{0} is not an https URL")]
    InsecureUrl(String),
    #[error("{0} is not a valid URL")]
    InvalidUrl(String),
    #[error("request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("server answered {0}")]
    Status(u16),
    #[error("response is larger than the {limit} byte limit")]
    TooLarge { limit: u64 },
    #[error("cannot read response: {0}")]
    Read(#[from] std::io::Error),
}

/// Plain http is accepted only for loopback, which exists for local feeds and tests; nothing remote can use it.
fn is_allowed_start(url: &Url) -> bool {
    if url.scheme() == "https" {
        return true;
    }
    if url.scheme() != "http" {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    host == "localhost"
        || host
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

pub struct HttpFetcher;

impl Fetcher for HttpFetcher {
    fn open(&self, url: &str, timeout: Duration) -> Result<Box<dyn Read>, FetchError> {
        let parsed = Url::parse(url).map_err(|_| FetchError::InvalidUrl(url.to_string()))?;
        if !is_allowed_start(&parsed) {
            return Err(FetchError::InsecureUrl(url.to_string()));
        }
        let client = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(timeout)
            .redirect(Policy::custom(|attempt| {
                if attempt.previous().len() >= MAX_REDIRECTS {
                    return attempt.error("too many redirects");
                }
                if attempt.url().scheme() != "https" {
                    return attempt.error("redirect to a non-https URL refused");
                }
                attempt.follow()
            }))
            .build()?;
        let response = client.get(parsed).send()?;
        if !response.status().is_success() {
            return Err(FetchError::Status(response.status().as_u16()));
        }
        Ok(Box::new(response))
    }
}

/// Reads at most `limit` bytes and fails if the source has more.
pub fn read_capped(reader: impl Read, limit: u64) -> Result<Vec<u8>, FetchError> {
    let mut bytes = vec![];
    reader.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(FetchError::TooLarge { limit });
    }
    Ok(bytes)
}
