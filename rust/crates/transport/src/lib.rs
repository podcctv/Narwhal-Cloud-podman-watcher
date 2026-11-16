#![forbid(unsafe_code)]

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ureq::tls::{PemItem, RootCerts, TlsConfig};
use ureq::Agent;

pub const HEADER_TIMESTAMP: &str = "X-Timestamp";
pub const HEADER_SIGNATURE: &str = "X-Signature";
pub const HEADER_RESPONSE_SIGNATURE: &str = "X-Narwhal-Response-Signature";

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

const SHA256_BLOCK_LEN: usize = 64;

const SHA256_H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Streaming pure-Rust SHA-256 hasher (FIPS 180-4).
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; SHA256_BLOCK_LEN],
    buffer_len: usize,
    total_len: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: SHA256_H0,
            buffer: [0u8; SHA256_BLOCK_LEN],
            buffer_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        let mut offset = 0usize;

        if self.buffer_len > 0 {
            let need = SHA256_BLOCK_LEN - self.buffer_len;
            if data.len() < need {
                self.buffer[self.buffer_len..self.buffer_len + data.len()].copy_from_slice(data);
                self.buffer_len += data.len();
                return;
            }
            self.buffer[self.buffer_len..SHA256_BLOCK_LEN].copy_from_slice(&data[..need]);
            let block = self.buffer;
            compress_block(&mut self.state, &block);
            self.buffer_len = 0;
            offset = need;
        }

        while offset + SHA256_BLOCK_LEN <= data.len() {
            let mut block = [0u8; SHA256_BLOCK_LEN];
            block.copy_from_slice(&data[offset..offset + SHA256_BLOCK_LEN]);
            compress_block(&mut self.state, &block);
            offset += SHA256_BLOCK_LEN;
        }

        if offset < data.len() {
            let rem = data.len() - offset;
            self.buffer[..rem].copy_from_slice(&data[offset..]);
            self.buffer_len = rem;
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let total_bits = self.total_len.wrapping_mul(8);

        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..SHA256_BLOCK_LEN].fill(0);
            let block = self.buffer;
            compress_block(&mut self.state, &block);
            self.buffer_len = 0;
        }

        self.buffer[self.buffer_len..56].fill(0);
        self.buffer[56..64].copy_from_slice(&total_bits.to_be_bytes());
        let block = self.buffer;
        compress_block(&mut self.state, &block);

        let mut out = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

fn compress_block(state: &mut [u32; 8], block: &[u8; SHA256_BLOCK_LEN]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

pub fn encode_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn sha256_hex(data: &[u8]) -> String {
    encode_hex_lower(&sha256(data))
}

pub fn hmac_sha256_parts(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut k0 = [0u8; SHA256_BLOCK_LEN];
    if key.len() > SHA256_BLOCK_LEN {
        let hashed = sha256(key);
        k0[..32].copy_from_slice(&hashed);
    } else {
        k0[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; SHA256_BLOCK_LEN];
    let mut opad = [0x5cu8; SHA256_BLOCK_LEN];
    for i in 0..SHA256_BLOCK_LEN {
        ipad[i] ^= k0[i];
        opad[i] ^= k0[i];
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    for part in parts {
        inner.update(part);
    }
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_digest);
    outer.finalize()
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    hmac_sha256_parts(key, &[data])
}

pub fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    encode_hex_lower(&hmac_sha256(key, data))
}

/// Matches Python `hmac.new(secret.encode(), body + str(ts).encode(), hashlib.sha256).hexdigest()`.
pub fn sign_payload(body: &[u8], secret: &str, timestamp: i64) -> String {
    let ts_str = timestamp.to_string();
    let digest = hmac_sha256_parts(secret.as_bytes(), &[body, ts_str.as_bytes()]);
    encode_hex_lower(&digest)
}

/// Constant-time byte-slice equality comparison.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= std::hint::black_box(x ^ y);
    }
    std::hint::black_box(diff) == 0
}

/// Verifies a lowercase hex HMAC-SHA256 signature in constant time.
pub fn verify_hmac_hex(secret: &str, body: &[u8], timestamp: i64, signature_hex: &str) -> bool {
    let expected = sign_payload(body, secret, timestamp);
    constant_time_eq(expected.as_bytes(), signature_hex.as_bytes())
}

/// Normalizes a server base URL, matching `client/agent.py:normalize_server_url`.
pub fn normalize_server_url(server: &str) -> String {
    let cleaned = server.trim();
    if cleaned.is_empty() {
        return "https://127.0.0.1:8080".to_string();
    }
    if !cleaned.contains("://") {
        return format!("https://{cleaned}");
    }
    cleaned.to_string()
}

#[derive(Debug)]
pub enum TransportError {
    Io(std::io::Error),
    TlsConfig(String),
    HttpStatus { status: u16, message: String },
    Http(String),
    ResponseTooLarge { max_bytes: usize },
    MissingResponseSignature,
    InvalidResponseSignature,
    SystemTime(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::TlsConfig(msg) => write!(f, "TLS configuration error: {msg}"),
            Self::HttpStatus { status, message } => {
                write!(f, "HTTP error status {status}: {message}")
            }
            Self::Http(msg) => write!(f, "HTTP transport error: {msg}"),
            Self::ResponseTooLarge { max_bytes } => {
                write!(f, "response body exceeded limit of {max_bytes} bytes")
            }
            Self::MissingResponseSignature => {
                write!(f, "missing {HEADER_RESPONSE_SIGNATURE} header")
            }
            Self::InvalidResponseSignature => {
                write!(f, "server response signature verification failed")
            }
            Self::SystemTime(msg) => write!(f, "system clock error: {msg}"),
        }
    }
}

impl std::error::Error for TransportError {}

#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub server_url: String,
    pub shared_secret: String,
    pub timeout: Duration,
    pub max_response_bytes: usize,
    pub ca_cert_path: Option<PathBuf>,
}

impl TransportConfig {
    pub fn new(server_url: impl Into<String>, shared_secret: impl Into<String>) -> Self {
        Self {
            server_url: server_url.into(),
            shared_secret: shared_secret.into(),
            timeout: DEFAULT_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            ca_cert_path: None,
        }
    }

    pub fn with_ca_cert_path(mut self, path: Option<&Path>) -> Self {
        self.ca_cert_path = path.map(Path::to_path_buf);
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_max_response_bytes(mut self, max_bytes: usize) -> Self {
        self.max_response_bytes = max_bytes;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub response_signature: Option<String>,
}

pub struct TransportClient {
    agent: Agent,
    base_url: String,
    shared_secret: String,
    max_response_bytes: usize,
}

impl TransportClient {
    pub fn new(config: TransportConfig) -> Result<Self, TransportError> {
        let base_url = normalize_server_url(&config.server_url)
            .trim_end_matches('/')
            .to_string();

        let mut builder = Agent::config_builder().timeout_global(Some(config.timeout));

        if let Some(ref ca_path) = config.ca_cert_path {
            let tls_config = build_custom_tls_config(ca_path)?;
            builder = builder.tls_config(tls_config);
        }

        let agent: Agent = builder.build().into();

        Ok(Self {
            agent,
            base_url,
            shared_secret: config.shared_secret,
            max_response_bytes: config.max_response_bytes,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn post_json_signed(
        &self,
        path: &str,
        body: &[u8],
    ) -> Result<SignedResponse, TransportError> {
        let ts = current_unix_timestamp()?;
        self.post_json_signed_at(path, body, ts, false)
    }

    pub fn post_json_signed_verified(
        &self,
        path: &str,
        body: &[u8],
    ) -> Result<SignedResponse, TransportError> {
        let ts = current_unix_timestamp()?;
        self.post_json_signed_at(path, body, ts, true)
    }

    pub fn post_json_signed_at(
        &self,
        path: &str,
        body: &[u8],
        timestamp: i64,
        verify_response_sig: bool,
    ) -> Result<SignedResponse, TransportError> {
        let url = join_url(&self.base_url, path);
        let ts_str = timestamp.to_string();
        let signature = sign_payload(body, &self.shared_secret, timestamp);

        let response = self
            .agent
            .post(&url)
            .header("Content-Type", "application/json")
            .header(HEADER_TIMESTAMP, &ts_str)
            .header(HEADER_SIGNATURE, &signature)
            .send(body)
            .map_err(map_ureq_error)?;

        self.read_and_verify_response(response, timestamp, verify_response_sig)
    }

    pub fn get_signed(
        &self,
        path: &str,
        verify_response_sig: bool,
    ) -> Result<SignedResponse, TransportError> {
        let ts = current_unix_timestamp()?;
        self.get_signed_at(path, ts, verify_response_sig)
    }

    pub fn get_signed_at(
        &self,
        path: &str,
        timestamp: i64,
        verify_response_sig: bool,
    ) -> Result<SignedResponse, TransportError> {
        let url = join_url(&self.base_url, path);
        let ts_str = timestamp.to_string();
        let signature = sign_payload(b"", &self.shared_secret, timestamp);

        let response = self
            .agent
            .get(&url)
            .header(HEADER_TIMESTAMP, &ts_str)
            .header(HEADER_SIGNATURE, &signature)
            .call()
            .map_err(map_ureq_error)?;

        self.read_and_verify_response(response, timestamp, verify_response_sig)
    }

    fn read_and_verify_response(
        &self,
        mut response: ureq::http::Response<ureq::Body>,
        timestamp: i64,
        verify_response_sig: bool,
    ) -> Result<SignedResponse, TransportError> {
        let status = response.status().as_u16();
        let response_signature = response
            .headers()
            .get(HEADER_RESPONSE_SIGNATURE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);

        let body = response
            .body_mut()
            .with_config()
            .limit(self.max_response_bytes as u64)
            .read_to_vec()
            .map_err(|err| match err {
                ureq::Error::BodyExceedsLimit(_) => TransportError::ResponseTooLarge {
                    max_bytes: self.max_response_bytes,
                },
                other => map_ureq_error(other),
            })?;

        if body.len() > self.max_response_bytes {
            return Err(TransportError::ResponseTooLarge {
                max_bytes: self.max_response_bytes,
            });
        }

        if verify_response_sig {
            let received = response_signature
                .as_deref()
                .filter(|s| !s.is_empty())
                .ok_or(TransportError::MissingResponseSignature)?;
            if !verify_hmac_hex(&self.shared_secret, &body, timestamp, received) {
                return Err(TransportError::InvalidResponseSignature);
            }
        }

        Ok(SignedResponse {
            status,
            body,
            response_signature,
        })
    }
}

fn build_custom_tls_config(ca_path: &Path) -> Result<TlsConfig, TransportError> {
    let pem_bytes = fs::read(ca_path).map_err(TransportError::Io)?;
    let mut certs = Vec::new();
    for item in ureq::tls::parse_pem(&pem_bytes) {
        match item {
            Ok(PemItem::Certificate(cert)) => certs.push(cert),
            Ok(_) => {}
            Err(err) => return Err(TransportError::TlsConfig(err.to_string())),
        }
    }
    if certs.is_empty() {
        return Err(TransportError::TlsConfig(format!(
            "no X.509 certificates found in CA PEM file: {}",
            ca_path.display()
        )));
    }
    Ok(TlsConfig::builder()
        .root_certs(RootCerts::new_with_certs(&certs))
        .build())
}

fn join_url(base_url: &str, path: &str) -> String {
    if path.starts_with('/') {
        format!("{base_url}{path}")
    } else {
        format!("{base_url}/{path}")
    }
}

fn current_unix_timestamp() -> Result<i64, TransportError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|err| TransportError::SystemTime(err.to_string()))
}

fn map_ureq_error(err: ureq::Error) -> TransportError {
    match err {
        ureq::Error::StatusCode(status) => TransportError::HttpStatus {
            status,
            message: format!("HTTP status {status}"),
        },
        ureq::Error::Io(io_err) => TransportError::Io(io_err),
        other => TransportError::Http(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn test_sha256_nist_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn test_sha256_streaming_equals_oneshot() {
        let msg = b"narwhal-cloud-podman-watcher-streaming-sha256-test-payload";
        let mut h = Sha256::new();
        h.update(&msg[..7]);
        h.update(&msg[7..29]);
        h.update(&msg[29..]);
        assert_eq!(h.finalize(), sha256(msg));
    }

    #[test]
    fn test_hmac_sha256_vectors() {
        // RFC 4231 Test Case 1
        let key = [0x0bu8; 20];
        assert_eq!(
            hmac_sha256_hex(&key, b"Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );

        // Key longer than 64 bytes (hashed down to 32 bytes first)
        let long_key = vec![b'k'; 100];
        assert_eq!(
            hmac_sha256_hex(&long_key, b"data"),
            "09380ee4b802da2363bc96e8e0d133ba275458ea8ddbc564f986fc12b31f8cb1"
        );

        // Matches Python: hmac.new(b"my-secret", b"{host:n1}" + b"1700000000", hashlib.sha256).hexdigest()
        assert_eq!(
            sign_payload(b"{host:n1}", "my-secret", 1_700_000_000),
            "fecd8e0b7d4c2555eb7793a63ac25fc3643ab09e27b4524e969a4a68ad36e82e"
        );
    }

    #[test]
    fn test_constant_time_compare_and_verify_hmac_hex() {
        assert!(constant_time_eq(b"abcdef", b"abcdef"));
        assert!(!constant_time_eq(b"abcdef", b"abcdeg"));
        assert!(!constant_time_eq(b"abcdef", b"abcde"));

        let sig = sign_payload(b"{\"ok\":true}", "secret-key", 1_700_000_123);
        assert!(verify_hmac_hex(
            "secret-key",
            b"{\"ok\":true}",
            1_700_000_123,
            &sig
        ));
        assert!(!verify_hmac_hex(
            "secret-key",
            b"{\"ok\":true}",
            1_700_000_124,
            &sig
        ));
        assert!(!verify_hmac_hex(
            "wrong-key",
            b"{\"ok\":true}",
            1_700_000_123,
            &sig
        ));
        assert!(!verify_hmac_hex(
            "secret-key",
            b"{\"ok\":true}",
            1_700_000_123,
            &sig.to_uppercase()
        ));
    }

    #[test]
    fn test_normalize_server_url() {
        assert_eq!(normalize_server_url(""), "https://127.0.0.1:8080");
        assert_eq!(normalize_server_url("   "), "https://127.0.0.1:8080");
        assert_eq!(
            normalize_server_url("monitor.example.com:8443"),
            "https://monitor.example.com:8443"
        );
        assert_eq!(
            normalize_server_url("http://127.0.0.1:8080"),
            "http://127.0.0.1:8080"
        );
    }

    #[test]
    fn test_missing_or_empty_ca_cert_fails() {
        let missing = PathBuf::from("nonexistent-narwhal-ca-cert-12345.pem");
        let err = TransportClient::new(
            TransportConfig::new("https://127.0.0.1:8080", "sec")
                .with_ca_cert_path(Some(&missing)),
        )
        .err()
        .expect("missing CA cert must fail");
        assert!(matches!(err, TransportError::Io(_)));

        let tmp = std::env::temp_dir().join(format!(
            "narwhal-empty-ca-{}.pem",
            std::process::id()
        ));
        fs::write(&tmp, b"not a pem certificate\n").unwrap();
        let err2 = TransportClient::new(
            TransportConfig::new("https://127.0.0.1:8080", "sec").with_ca_cert_path(Some(&tmp)),
        )
        .err()
        .expect("empty PEM must fail");
        let _ = fs::remove_file(&tmp);
        assert!(matches!(err2, TransportError::TlsConfig(_)));
    }

    struct CapturedRequest {
        request_line: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    }

    fn spawn_one_shot_http_server(
        response_status: &str,
        extra_headers: Vec<(String, String)>,
        response_body: Vec<u8>,
    ) -> (String, thread::JoinHandle<CapturedRequest>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind localhost");
        let addr = listener.local_addr().unwrap();
        let status_line = response_status.to_string();

        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut reader = BufReader::new(stream.try_clone().unwrap());

            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();

            let mut headers = HashMap::new();
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
                if trimmed.is_empty() {
                    break;
                }
                if let Some((k, v)) = trimmed.split_once(':') {
                    let key = k.trim().to_ascii_lowercase();
                    let val = v.trim().to_string();
                    if key == "content-length" {
                        content_length = val.parse().unwrap_or(0);
                    }
                    headers.insert(key, val);
                }
            }

            let mut body = vec![0u8; content_length];
            if content_length > 0 {
                reader.read_exact(&mut body).unwrap();
            }

            let mut raw_resp = format!(
                "HTTP/1.1 {status_line}\r\nContent-Length: {}\r\nConnection: close\r\n",
                response_body.len()
            );
            for (k, v) in extra_headers {
                raw_resp.push_str(&format!("{k}: {v}\r\n"));
            }
            raw_resp.push_str("\r\n");

            stream.write_all(raw_resp.as_bytes()).unwrap();
            stream.write_all(&response_body).unwrap();
            stream.flush().unwrap();

            CapturedRequest {
                request_line: request_line.trim().to_string(),
                headers,
                body,
            }
        });

        (format!("http://{addr}"), handle)
    }

    #[test]
    fn test_local_http_signed_post_headers_and_body() {
        let secret = "test-shared-secret";
        let payload = br#"{"host_id":"node-1","timestamp":1700000500}"#;
        let ts = 1_700_000_500i64;
        let resp_body = br#"{"ok":true}"#.to_vec();
        let resp_sig = sign_payload(&resp_body, secret, ts);

        let (base_url, handle) = spawn_one_shot_http_server(
            "200 OK",
            vec![(HEADER_RESPONSE_SIGNATURE.to_string(), resp_sig)],
            resp_body.clone(),
        );

        let client = TransportClient::new(TransportConfig::new(base_url, secret)).unwrap();
        let resp = client
            .post_json_signed_at("/api/v1/actions/poll", payload, ts, true)
            .expect("signed POST should succeed");

        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, resp_body);

        let req = handle.join().unwrap();
        assert!(req.request_line.starts_with("POST /api/v1/actions/poll HTTP/"));
        assert_eq!(
            req.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(
            req.headers.get("x-timestamp").map(String::as_str),
            Some("1700000500")
        );
        let received_sig = req
            .headers
            .get("x-signature")
            .expect("X-Signature header must be present");
        assert!(verify_hmac_hex(secret, &req.body, ts, received_sig));
        assert_eq!(req.body, payload);
    }

    #[test]
    fn test_local_http_response_signature_rejection() {
        let secret = "test-shared-secret";
        let ts = 1_700_000_600i64;

        // Invalid signature
        let (base_url, handle) = spawn_one_shot_http_server(
            "200 OK",
            vec![(HEADER_RESPONSE_SIGNATURE.to_string(), "deadbeef".to_string())],
            br#"{"actions":[]}"#.to_vec(),
        );
        let client = TransportClient::new(TransportConfig::new(base_url, secret)).unwrap();
        let err = client
            .post_json_signed_at("/api/v1/actions/poll", b"{}", ts, true)
            .expect_err("tampered response signature must fail");
        let _ = handle.join();
        assert!(matches!(err, TransportError::InvalidResponseSignature));

        // Missing signature
        let (base_url2, handle2) =
            spawn_one_shot_http_server("200 OK", vec![], br#"{"actions":[]}"#.to_vec());
        let client2 = TransportClient::new(TransportConfig::new(base_url2, secret)).unwrap();
        let err2 = client2
            .post_json_signed_at("/api/v1/actions/poll", b"{}", ts, true)
            .expect_err("missing response signature must fail");
        let _ = handle2.join();
        assert!(matches!(err2, TransportError::MissingResponseSignature));
    }

    #[test]
    fn test_local_http_bounded_response_size() {
        let (base_url, handle) =
            spawn_one_shot_http_server("200 OK", vec![], vec![b'a'; 1024]);
        let client = TransportClient::new(
            TransportConfig::new(base_url, "sec").with_max_response_bytes(128),
        )
        .unwrap();
        let err = client
            .get_signed_at("/api/v1/update/probe/sha256", 1_700_000_700, false)
            .expect_err("oversized response must be rejected");
        let _ = handle.join();
        assert!(matches!(
            err,
            TransportError::ResponseTooLarge { max_bytes: 128 }
        ));
    }
}
