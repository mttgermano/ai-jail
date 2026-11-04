//! `--secret-provider`: fetch `--env NAME` values from a self-hosted
//! vault (1Password Connect or OpenBao KV v2) on the host, before the
//! sandbox starts. The values are spliced back into `env_pass` as
//! explicit `NAME=VALUE` entries, so phantom secrets (`--secret
//! KEY=host`) keep working unchanged.
//!
//! Least privilege is layered: a scoped provider token (read access to
//! one vault / one path prefix), the `secret_refs` allowlist in trusted
//! config, and the per-launch `--env NAME` request. A fetched key never
//! falls back to the local environment, and the provider token never
//! reaches the sandbox.

use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

/// Which vault backend to talk to. Stored in config as a string and
/// parsed at use time, so an old binary reading a newer type string
/// never breaks config loading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    OnePassword,
    OpenBao,
}

impl Kind {
    /// Parse a provider type name. Aliases: `op` for 1Password, `bao`
    /// for OpenBao.
    pub fn parse(s: &str) -> Result<Kind, String> {
        match s {
            "onepassword" | "op" => Ok(Kind::OnePassword),
            "openbao" | "bao" => Ok(Kind::OpenBao),
            other => Err(format!(
                "unknown secret provider type {other:?} \
                 (expected \"onepassword\", \"op\", \"openbao\", or \"bao\")"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::OnePassword => "onepassword",
            Kind::OpenBao => "openbao",
        }
    }
}

/// Parsed provider server root: scheme + host + optional port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Base {
    /// `https`, or plain `http` allowed only for loopback hosts.
    pub https: bool,
    /// Host name or IP literal, without brackets.
    pub host: String,
    /// Explicit port; defaults to the scheme's well-known port.
    pub port: Option<u16>,
}

impl Base {
    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or(if self.https { 443 } else { 80 })
    }
}

/// Parse a provider server root URL. A trailing `/` or `/v1` is
/// stripped. HTTPS is required because the token travels in a header;
/// plain `http://` is allowed only for loopback hosts
/// (`127.0.0.1`, `::1`, `localhost`).
pub fn parse_url(input: &str) -> Result<Base, String> {
    let (scheme, rest) = input.split_once("://").ok_or_else(|| {
        format!("secret provider URL needs a scheme: {input:?}")
    })?;
    let https = match scheme.to_ascii_lowercase().as_str() {
        "https" => true,
        "http" => false,
        other => {
            return Err(format!(
                "secret provider URL scheme must be http or https, not {other:?}"
            ));
        }
    };
    let mut rest = rest.trim_end_matches('/').to_string();
    if let Some(stripped) = rest.strip_suffix("/v1") {
        rest = stripped.to_string();
    }
    let rest = rest.trim_end_matches('/');
    if rest.is_empty() {
        return Err("secret provider URL has an empty host".into());
    }
    if rest.contains(['/', '?', '#']) {
        return Err(format!(
            "secret provider URL must be a server root (scheme://host[:port]), not {input:?}"
        ));
    }

    let (host, port) = if let Some(inner) = rest.strip_prefix('[') {
        // Bracketed IPv6 literal, optionally [::1]:8080.
        let Some((ip, after)) = inner.split_once(']') else {
            return Err(format!(
                "secret provider URL has an unterminated [host]: {input:?}"
            ));
        };
        if ip.is_empty() {
            return Err("secret provider URL has an empty host".into());
        }
        let port = match after.strip_prefix(':') {
            Some(p) => Some(parse_port(p)?),
            None if after.is_empty() => None,
            None => {
                return Err(format!(
                    "unexpected text after [host] in secret provider URL: {input:?}"
                ));
            }
        };
        (ip.to_string(), port)
    } else if rest.matches(':').count() == 1 {
        let (h, p) = rest.split_once(':').expect("one colon");
        (h.to_string(), Some(parse_port(p)?))
    } else if rest.matches(':').count() == 0 {
        (rest.to_string(), None)
    } else {
        // Bare unbracketed IPv6 literal such as ::1.
        let ip: IpAddr = rest.parse().map_err(|_| {
            format!("secret provider URL host is not valid: {rest:?}")
        })?;
        (ip.to_string(), None)
    };

    if host.is_empty() {
        return Err("secret provider URL has an empty host".into());
    }
    if !https && !is_loopback_host(&host) {
        return Err(format!(
            "secret provider URL must use https (the token travels in a \
             request header); plain http is allowed only for loopback \
             hosts, not {host:?}"
        ));
    }
    Ok(Base { https, host, port })
}

fn parse_port(p: &str) -> Result<u16, String> {
    p.parse::<u16>()
        .map_err(|_| format!("secret provider URL port is not valid: {p:?}"))
}

/// The three literal hosts allowed to speak plain http. "localhost"
/// that resolves elsewhere is the user's own hosts-file lie to make.
fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Validate a provider reference for the given backend.
///
/// 1Password: `Vault/Item/field` — three non-empty segments, each a
/// name or a 26-char ID.
/// OpenBao: `mount/path#field` — at least two `/`-separated segments
/// before `#` (the first is the KV v2 mount), plus a non-empty field.
///
/// All segments must be non-empty, must not be `.` or `..`, and must
/// not contain control characters.
pub fn validate_ref(kind: Kind, r: &str) -> Result<(), String> {
    let reject_segment = |seg: &str, what: &str| -> Result<(), String> {
        if seg.is_empty() {
            return Err(format!("empty {what} in secret ref"));
        }
        if seg == "." || seg == ".." {
            return Err(format!("{what} must not be {seg:?}"));
        }
        if seg.bytes().any(|b| b.is_ascii_control()) {
            return Err(format!("{what} contains a control character"));
        }
        Ok(())
    };
    match kind {
        Kind::OnePassword => {
            if r.starts_with('/') || r.ends_with('/') {
                return Err("secret ref must be Vault/Item/field with no leading or trailing slash".into());
            }
            let parts: Vec<&str> = r.split('/').collect();
            if parts.len() != 3 {
                return Err(format!(
                    "1Password secret ref must be Vault/Item/field, not {r:?}"
                ));
            }
            for (i, seg) in parts.iter().enumerate() {
                let what = ["vault", "item", "field"][i];
                reject_segment(seg, what)
                    .map_err(|e| format!("secret ref {r:?}: {e}"))?;
            }
            Ok(())
        }
        Kind::OpenBao => {
            if r.starts_with('/') {
                return Err(
                    "secret ref must be mount/path#field with no leading slash"
                        .into(),
                );
            }
            let Some((path, field)) = r.split_once('#') else {
                return Err(format!(
                    "OpenBao secret ref must be mount/path#field, not {r:?}"
                ));
            };
            reject_segment(field, "field")
                .map_err(|e| format!("secret ref {r:?}: {e}"))?;
            let segments: Vec<&str> = path.split('/').collect();
            if segments.len() < 2 {
                return Err(format!(
                    "secret ref {r:?}: the path before # must include the KV v2 mount \
                     and a secret path (mount/path)"
                ));
            }
            for (i, seg) in segments.iter().enumerate() {
                let what = if i == 0 { "mount" } else { "path segment" };
                reject_segment(seg, what)
                    .map_err(|e| format!("secret ref {r:?}: {e}"))?;
            }
            Ok(())
        }
    }
}

/// Percent-encode a path segment for a request URL. Kept local so the
/// client stays dependency-free.
pub(crate) fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Escape a value destined for inside a double-quoted filter expression
/// (1Password Connect `filter=name eq "..."`).
pub(crate) fn escape_filter_value(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Maximum accepted secret value size, and the value sanity check:
/// non-empty, at most 4096 bytes, no control characters. One trailing
/// newline is stripped before those checks.
pub(crate) fn check_value(raw: &str) -> Result<String, String> {
    let value = raw.strip_suffix('\n').unwrap_or(raw);
    if value.is_empty() {
        return Err("secret value is empty".into());
    }
    if value.len() > 4096 {
        return Err(format!(
            "secret value is too large ({} bytes, max 4096)",
            value.len()
        ));
    }
    if value.bytes().any(|b| b.is_ascii_control()) {
        return Err("secret value contains a control character".into());
    }
    Ok(value.to_string())
}

/// Format a backend error: it names the env KEY, the ref and the
/// detail (HTTP status or parse failure) — never the value, the token
/// or the response body.
pub(crate) fn err_ctx(key: &str, r: &str, detail: &str) -> String {
    format!("secret {key} ({r}): {detail}")
}

/// Fetch every wanted key from the provider, returning
/// `(env key, value)` pairs in the same order as `wanted`. Any failure
/// aborts the whole batch: the caller must not fall back to the local
/// environment for a key it asked the provider about.
pub fn fetch(
    kind: Kind,
    base: &Base,
    ca_path: Option<&Path>,
    token: &str,
    wanted: &[(String, String)],
) -> Result<Vec<(String, String)>, String> {
    if wanted.is_empty() {
        return Ok(Vec::new());
    }
    if token.is_empty() {
        return Err("secret provider token is empty".into());
    }
    match kind {
        Kind::OnePassword => fetch_onepassword(base, ca_path, token, wanted),
        Kind::OpenBao => fetch_openbao(base, ca_path, token, wanted),
    }
}

/// OpenBao KV v2 backend: ref `mount/path#field` →
/// `GET /v1/<mount>/data/<path>` → `.data.data.<field>`, which must be
/// a JSON string. Header `X-Vault-Token: <token>`.
///
/// TODO(openbao): implement. Shared helpers available:
/// `http_get_json`, `percent_encode`, `check_value`, `err_ctx`.
fn fetch_openbao(
    _base: &Base,
    _ca_path: Option<&Path>,
    _token: &str,
    wanted: &[(String, String)],
) -> Result<Vec<(String, String)>, String> {
    Err(format!(
        "openbao backend not implemented ({} keys wanted)",
        wanted.len()
    ))
}

/// 1Password Connect backend: ref `Vault/Item/field`. Each of vault
/// and item is a name or a 26-char ID; a name is resolved with a
/// filtered list query (exactly one match required) and cached for the
/// launch. `GET /v1/vaults/<vid>/items/<iid>` returns `fields[]`;
/// match by `label` first, then `id`, exactly one match, take `value`.
/// Header `Authorization: Bearer <token>`.
///
/// TODO(onepassword): implement. Shared helpers available:
/// `http_get_json`, `percent_encode`, `escape_filter_value`,
/// `check_value`, `err_ctx`.
fn fetch_onepassword(
    _base: &Base,
    _ca_path: Option<&Path>,
    _token: &str,
    wanted: &[(String, String)],
) -> Result<Vec<(String, String)>, String> {
    Err(format!(
        "onepassword backend not implemented ({} keys wanted)",
        wanted.len()
    ))
}

// ---------------------------------------------------------------------------
// Minimal HTTP/1.1 GET client
// ---------------------------------------------------------------------------

/// Connect timeout for the provider TCP connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Read/write timeouts once connected.
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// Hard cap on any response body, whatever the framing says.
const MAX_BODY: u64 = 1024 * 1024;
/// Sanity cap on the response header block.
const MAX_HEAD: usize = 64 * 1024;

/// Issue one authenticated `GET` against the provider and parse the
/// response body as JSON. `path` must start with `/` and already be
/// percent-encoded. Non-2xx responses are an error that names only the
/// HTTP status; the body is never echoed into errors, so neither the
/// secret value nor the token can leak through a message.
pub(crate) fn http_get_json(
    base: &Base,
    ca_path: Option<&Path>,
    headers: &[(&str, &str)],
    path: &str,
) -> Result<serde_json::Value, String> {
    let mut stream = connect(base, ca_path)?;
    let host_header = match base.port {
        Some(p) => format!("{}:{p}", base.host),
        None => base.host.clone(),
    };
    let mut req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n"
    );
    for (name, value) in headers {
        req.push_str(name);
        req.push_str(": ");
        req.push_str(value);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("provider request failed: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("provider request failed: {e}"))?;

    let (status, framing) = read_head(stream.as_mut())?;
    let body = read_body(stream.as_mut(), &framing)?;
    if !(200..300).contains(&status) {
        return Err(format!("HTTP {status}"));
    }
    serde_json::from_slice(&body)
        .map_err(|_| "provider response is not valid JSON".to_string())
}

/// Dial the provider: plain TCP for loopback http, rustls for https.
/// Deliberately NOT the filtered-egress `connect_upstream`: its SSRF
/// guard would block the private address the user configured on
/// purpose. DNS resolution happens per request here — there is no
/// pinning concern for a single short GET.
fn connect(
    base: &Base,
    ca_path: Option<&Path>,
) -> Result<Box<dyn ReadWrite>, String> {
    let port = base.effective_port();
    let addrs: Vec<std::net::SocketAddr> = (base.host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| {
            format!("cannot resolve provider host {}: {e}", base.host)
        })?
        .collect();
    if addrs.is_empty() {
        return Err(format!("cannot resolve provider host {}", base.host));
    }
    let mut tcp_err = String::from("no addresses");
    let mut tcp = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(e) => tcp_err = format!("connect to {addr} failed: {e}"),
        }
    }
    let tcp = tcp.ok_or(tcp_err)?;
    let _ = tcp.set_read_timeout(Some(IO_TIMEOUT));
    let _ = tcp.set_write_timeout(Some(IO_TIMEOUT));
    if !base.https {
        return Ok(Box::new(tcp));
    }

    let mut roots = rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
    );
    if let Some(ca) = ca_path {
        for der in load_ca_pem(ca)? {
            roots.add(der).map_err(|_| {
                format!("cannot parse CA certificate in {}", ca.display())
            })?;
        }
    }
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = rustls::pki_types::ServerName::try_from(
        base.host.clone(),
    )
    .map_err(|_| {
        format!("provider host {:?} is not a valid TLS name", base.host)
    })?;
    let conn = rustls::ClientConnection::new(
        std::sync::Arc::new(tls_config),
        server_name,
    )
    .map_err(|e| format!("TLS setup for {} failed: {e}", base.host))?;
    Ok(Box::new(rustls::StreamOwned::new(conn, tcp)))
}

/// Load a PEM file of CA certificates (one or more blocks). The host
/// trusts webpki roots already; this adds the private CA the user
/// pointed at. There is deliberately no "skip verification" option.
fn load_ca_pem(
    path: &Path,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    use rustls::pki_types::pem::PemObject;
    let pem = std::fs::read(path)
        .map_err(|e| format!("cannot read CA file {}: {e}", path.display()))?;
    let text = String::from_utf8_lossy(&pem);
    let mut ders = Vec::new();
    let mut rest = text.as_ref();
    while let Some(begin) = rest.find("-----BEGIN ") {
        let Some(end_marker_start) = rest[begin..].find("-----END ") else {
            break;
        };
        let end = begin + end_marker_start;
        let block_end = rest[end..]
            .find("-----\n")
            .map_or(rest.len(), |i| end + i + "-----\n".len());
        let block = &rest[begin..block_end];
        let der =
            rustls::pki_types::CertificateDer::from_pem_slice(block.as_bytes())
                .map_err(|_| {
                    format!(
                        "cannot parse PEM certificate in {}",
                        path.display()
                    )
                })?;
        ders.push(der);
        rest = &rest[block_end..];
    }
    if ders.is_empty() {
        return Err(format!("no PEM certificates found in {}", path.display()));
    }
    Ok(ders)
}

trait ReadWrite: Read + Write {}
impl ReadWrite for TcpStream {}
impl ReadWrite for rustls::StreamOwned<rustls::ClientConnection, TcpStream> {}

/// Response framing decided by the header block.
struct Framing {
    content_length: Option<u64>,
    chunked: bool,
}

/// Read and parse the response head (status line + headers), up to and
/// including the blank line.
fn read_head(stream: &mut dyn ReadWrite) -> Result<(u16, Framing), String> {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        if head.len() > MAX_HEAD {
            return Err("provider response header block is too large".into());
        }
        match stream.read(&mut byte) {
            Ok(0) => {
                return Err(
                    "provider closed the connection before sending a response"
                        .into(),
                );
            }
            Ok(_) => head.push(byte[0]),
            Err(e) => return Err(format!("provider response failed: {e}")),
        }
        if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&head);
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| {
            "provider response has no HTTP status line".to_string()
        })?;
    let mut content_length = None;
    let mut chunked = false;
    for line in head.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "content-length" => content_length = value.parse::<u64>().ok(),
            "transfer-encoding" => {
                chunked = value.to_ascii_lowercase().contains("chunked")
            }
            _ => {}
        }
    }
    Ok((
        status,
        Framing {
            content_length,
            chunked,
        },
    ))
}

/// Read the body according to the framing, capped at `MAX_BODY`.
fn read_body(
    stream: &mut dyn ReadWrite,
    framing: &Framing,
) -> Result<Vec<u8>, String> {
    if framing.chunked {
        return read_chunked(stream);
    }
    match framing.content_length {
        Some(len) => {
            if len > MAX_BODY {
                return Err("provider response is too large".into());
            }
            let mut body = vec![0_u8; len as usize];
            stream
                .read_exact(&mut body)
                .map_err(|e| format!("provider response failed: {e}"))?;
            Ok(body)
        }
        None => {
            // Connection: close framing: read to EOF under the cap.
            let mut body = Vec::new();
            let mut chunk = [0_u8; 8192];
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        if body.len() + n > MAX_BODY as usize {
                            return Err("provider response is too large".into());
                        }
                        body.extend_from_slice(&chunk[..n]);
                    }
                    Err(e) => {
                        return Err(format!("provider response failed: {e}"));
                    }
                }
            }
            Ok(body)
        }
    }
}

/// Decode a chunked body (`Transfer-Encoding: chunked`), capped at
/// `MAX_BODY` across all chunks.
fn read_chunked(stream: &mut dyn ReadWrite) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    loop {
        let line = read_line(stream)?;
        let size = usize::from_str_radix(
            line.trim().split(';').next().unwrap_or("").trim(),
            16,
        )
        .map_err(|_| {
            "provider response has a malformed chunk size".to_string()
        })?;
        if body.len() + size > MAX_BODY as usize {
            return Err("provider response is too large".into());
        }
        if size == 0 {
            // Trailers until the blank line, then done.
            loop {
                let trailer = read_line(stream)?;
                if trailer == "\r\n" || trailer == "\n" || trailer.is_empty() {
                    break;
                }
            }
            return Ok(body);
        }
        let mut chunk = vec![0_u8; size];
        stream
            .read_exact(&mut chunk)
            .map_err(|e| format!("provider response failed: {e}"))?;
        body.extend_from_slice(&chunk);
        let _ = read_line(stream)?; // trailing CRLF after each chunk
    }
}

/// Read one CRLF- (or LF-) terminated line, bounded.
fn read_line(stream: &mut dyn ReadWrite) -> Result<String, String> {
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        if line.len() > MAX_HEAD {
            return Err("provider response has an over-long line".into());
        }
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                line.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            Err(e) => return Err(format!("provider response failed: {e}")),
        }
    }
    String::from_utf8(line)
        .map_err(|_| "provider response is not UTF-8".to_string())
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_parse_accepts_names_and_aliases() {
        assert_eq!(Kind::parse("onepassword"), Ok(Kind::OnePassword));
        assert_eq!(Kind::parse("op"), Ok(Kind::OnePassword));
        assert_eq!(Kind::parse("openbao"), Ok(Kind::OpenBao));
        assert_eq!(Kind::parse("bao"), Ok(Kind::OpenBao));
    }

    #[test]
    fn kind_parse_rejects_unknown() {
        let err = Kind::parse("vaultwarden").unwrap_err();
        assert!(err.contains("vaultwarden"), "{err}");
        assert!(
            err.contains("onepassword") && err.contains("openbao"),
            "{err}"
        );
        assert!(Kind::parse("").is_err());
    }

    #[test]
    fn url_parses_scheme_host_port() {
        let b = parse_url("https://10.0.0.5:8080").unwrap();
        assert!(b.https);
        assert_eq!(b.host, "10.0.0.5");
        assert_eq!(b.port, Some(8080));
    }

    #[test]
    fn url_strips_trailing_slash_and_v1() {
        for input in [
            "https://bao.internal:8200",
            "https://bao.internal:8200/",
            "https://bao.internal:8200/v1",
            "https://bao.internal:8200/v1/",
        ] {
            let b = parse_url(input).unwrap();
            assert_eq!(b.host, "bao.internal");
            assert_eq!(b.port, Some(8200), "{input}");
        }
    }

    #[test]
    fn url_keeps_ipv6_and_defaults() {
        let b = parse_url("https://[::1]:8200").unwrap();
        assert_eq!(b.host, "::1");
        assert_eq!(b.port, Some(8200));
        let b = parse_url("https://vault.example.com").unwrap();
        assert_eq!(b.port, None);
        assert_eq!(b.effective_port(), 443);
        let b = parse_url("http://127.0.0.1:8200").unwrap();
        assert_eq!(b.effective_port(), 8200);
    }

    #[test]
    fn url_rejects_bad_scheme() {
        assert!(parse_url("ftp://10.0.0.5").is_err());
        assert!(parse_url("10.0.0.5:8080").is_err());
    }

    #[test]
    fn url_rejects_http_for_non_loopback() {
        let err = parse_url("http://10.0.0.5:8080").unwrap_err();
        assert!(err.contains("https"), "{err}");
        // Loopback http is allowed.
        assert!(parse_url("http://127.0.0.1:8200").is_ok());
        assert!(parse_url("http://[::1]:8200").is_ok());
        assert!(parse_url("http://localhost:8200").is_ok());
    }

    #[test]
    fn url_rejects_paths_queries_and_empty_host() {
        assert!(parse_url("https://bao.internal:8200/ui").is_err());
        assert!(parse_url("https://bao.internal:8200/v1/x").is_err());
        assert!(parse_url("https://?x=1").is_err());
        assert!(parse_url("https://").is_err());
    }

    #[test]
    fn ref_validation_onepassword() {
        assert!(validate_ref(Kind::OnePassword, "Dev/Test/password").is_ok());
        assert!(
            validate_ref(Kind::OnePassword, "Dev/Item with space/a field")
                .is_ok()
        );
        // 26-char IDs are fine.
        assert!(
            validate_ref(
                Kind::OnePassword,
                "hqn4xa7hjkmz6fnz3a4uwsydce/Item/field"
            )
            .is_ok()
        );
        assert!(validate_ref(Kind::OnePassword, "Dev/Test").is_err());
        assert!(
            validate_ref(Kind::OnePassword, "Dev/Test/field/extra").is_err()
        );
        assert!(validate_ref(Kind::OnePassword, "/Test/field").is_err());
        assert!(validate_ref(Kind::OnePassword, "Dev/Test/").is_err());
        assert!(validate_ref(Kind::OnePassword, "Dev/../field").is_err());
        assert!(validate_ref(Kind::OnePassword, "Dev//field").is_err());
    }

    #[test]
    fn ref_validation_openbao() {
        assert!(validate_ref(Kind::OpenBao, "secret/ai/test#value").is_ok());
        assert!(
            validate_ref(Kind::OpenBao, "secret/deep/path#api_key").is_ok()
        );
        assert!(validate_ref(Kind::OpenBao, "secret/test#value").is_ok()); // mount + one path segment
        assert!(validate_ref(Kind::OpenBao, "secret/ai/test").is_err()); // missing #field
        assert!(validate_ref(Kind::OpenBao, "secret/ai/test#").is_err());
        assert!(validate_ref(Kind::OpenBao, "secret/../test#value").is_err());
        assert!(validate_ref(Kind::OpenBao, "/secret/ai#v").is_err());
        assert!(validate_ref(Kind::OpenBao, "secret//test#value").is_err());
    }

    #[test]
    fn percent_encoding() {
        assert_eq!(percent_encode("Dev"), "Dev");
        assert_eq!(percent_encode("a b"), "a%20b");
        assert_eq!(percent_encode("café"), "caf%C3%A9");
        assert_eq!(percent_encode("a/b?x=1#z"), "a%2Fb%3Fx%3D1%23z");
    }

    #[test]
    fn filter_escaping() {
        assert_eq!(escape_filter_value("plain"), "plain");
        assert_eq!(escape_filter_value("say \"hi\""), "say \\\"hi\\\"");
        assert_eq!(escape_filter_value("back\\slash"), "back\\\\slash");
    }

    #[test]
    fn value_checks() {
        assert_eq!(check_value("hello").unwrap(), "hello");
        assert_eq!(check_value("hello\n").unwrap(), "hello");
        assert!(check_value("hello\n\n").is_err()); // embedded newline is a control char
        assert!(check_value("").is_err());
        assert!(check_value("\n").is_err());
        assert!(check_value("a\tb").is_err()); // control char
        assert!(check_value(&"x".repeat(4097)).is_err());
        assert!(check_value(&"x".repeat(4096)).is_ok());
    }

    #[test]
    fn fetch_rejects_empty_token_and_empty_wanted() {
        let base = parse_url("http://127.0.0.1:8200").unwrap();
        assert!(
            fetch(
                Kind::OpenBao,
                &base,
                None,
                "",
                &[("K".into(), "m/p#f".into())]
            )
            .is_err()
        );
        assert_eq!(
            fetch(Kind::OpenBao, &base, None, "tok", &[]).unwrap(),
            Vec::<(String, String)>::new()
        );
    }
}

/// Tests for the OpenBao backend (canned JSON, no network).
#[cfg(test)]
mod openbao_tests {
    // TODO(openbao): backend tests.
}

/// Tests for the 1Password Connect backend (canned JSON, no network).
#[cfg(test)]
mod onepassword_tests {
    // TODO(onepassword): backend tests.
}
