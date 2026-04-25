// vim: set tw=79 cc=80 ts=4 sw=4 sts=4 et :
//
// Copyright (c) 2026 Murilo Ijanc' <murilo@ijanc.org>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//

//! Minimal HTTP/1.0 and HTTP/1.1 library.
//!
//! Conforms to RFC 1945 (HTTP/1.0) and RFC 2616 (HTTP/1.1).  Provides a
//! blocking client with TLS via LibreSSL's `libtls`, together with the
//! underlying protocol primitives: header parsing, chunked transfer-
//! coding, and message framing.
//!
//! The crate links `-ltls` unconditionally.
//!
//! # Example
//!
//! ```no_run
//! let resp = http::get("https://example.com/").send()?;
//! let body = resp.body_string()?;
//! # Ok::<(), http::Error>(())
//! ```

use std::error;
use std::ffi::{CStr, CString};
use std::fmt;
use std::fmt::Write as _;
use std::io::{self, BufRead, BufReader, Read, Take, Write};
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::os::raw::c_void;
use std::result;
use std::str;
use std::time::Duration;

/// Library version
pub const VERSION: &str = env!("HTTP_VERSION");

const DEFAULT_TIMEOUT_SECS: u64 = 30;
const MAX_HEAD_BYTES: usize = 64 * 1024;

//////////////////////////////////////////////////////////////////////////////
// Error
//////////////////////////////////////////////////////////////////////////////

/// A library error.  Carries a message and an optional byte position for
/// parse errors.
pub struct Error {
    msg: String,
    pos: usize,
}

impl Error {
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            msg: msg.into(),
            pos: 0,
        }
    }

    pub fn at(msg: impl Into<String>, pos: usize) -> Self {
        Self {
            msg: msg.into(),
            pos,
        }
    }

    pub fn message(&self) -> &str {
        &self.msg
    }

    pub fn position(&self) -> usize {
        self.pos
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Error")
            .field("msg", &self.msg)
            .field("pos", &self.pos)
            .finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.pos == 0 {
            f.write_str(&self.msg)
        } else {
            write!(f, "{} at byte {}", self.msg, self.pos)
        }
    }
}

impl error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::new(format!("io: {e}"))
    }
}

pub type Result<T> = result::Result<T, Error>;

//////////////////////////////////////////////////////////////////////////////
// Method
//////////////////////////////////////////////////////////////////////////////

/// An HTTP request method.  RFC 2616 §5.1.1.  Extension methods are
/// preserved in the `Other` variant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Options,
    Trace,
    Connect,
    Patch,
    Other(String),
}

impl Method {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Options => "OPTIONS",
            Self::Trace => "TRACE",
            Self::Connect => "CONNECT",
            Self::Patch => "PATCH",
            Self::Other(s) => s.as_str(),
        }
    }

    fn from_bytes(b: &[u8]) -> Self {
        match b {
            b"GET" => Self::Get,
            b"HEAD" => Self::Head,
            b"POST" => Self::Post,
            b"PUT" => Self::Put,
            b"DELETE" => Self::Delete,
            b"OPTIONS" => Self::Options,
            b"TRACE" => Self::Trace,
            b"CONNECT" => Self::Connect,
            b"PATCH" => Self::Patch,
            other => Self::Other(
                str::from_utf8(other).expect("token is ASCII").to_owned(),
            ),
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

//////////////////////////////////////////////////////////////////////////////
// Version
//////////////////////////////////////////////////////////////////////////////

/// An HTTP protocol version.  RFC 1945 §3.1, RFC 2616 §3.1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Version {
    Http10,
    Http11,
}

impl Version {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

//////////////////////////////////////////////////////////////////////////////
// Status
//////////////////////////////////////////////////////////////////////////////

/// An HTTP status code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status(pub u16);

impl Status {
    pub const fn code(self) -> u16 {
        self.0
    }

    pub const fn is_informational(self) -> bool {
        self.0 >= 100 && self.0 < 200
    }

    pub const fn is_success(self) -> bool {
        self.0 >= 200 && self.0 < 300
    }

    pub const fn is_redirection(self) -> bool {
        self.0 >= 300 && self.0 < 400
    }

    pub const fn is_client_error(self) -> bool {
        self.0 >= 400 && self.0 < 500
    }

    pub const fn is_server_error(self) -> bool {
        self.0 >= 500 && self.0 < 600
    }

    /// Canonical reason phrase from RFC 2616 §6.1.1.  Returns `None` for
    /// unregistered codes.
    pub const fn canonical_reason(self) -> Option<&'static str> {
        Some(match self.0 {
            100 => "Continue",
            101 => "Switching Protocols",
            200 => "OK",
            201 => "Created",
            202 => "Accepted",
            203 => "Non-Authoritative Information",
            204 => "No Content",
            205 => "Reset Content",
            206 => "Partial Content",
            300 => "Multiple Choices",
            301 => "Moved Permanently",
            302 => "Found",
            303 => "See Other",
            304 => "Not Modified",
            305 => "Use Proxy",
            307 => "Temporary Redirect",
            400 => "Bad Request",
            401 => "Unauthorized",
            402 => "Payment Required",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            406 => "Not Acceptable",
            407 => "Proxy Authentication Required",
            408 => "Request Timeout",
            409 => "Conflict",
            410 => "Gone",
            411 => "Length Required",
            412 => "Precondition Failed",
            413 => "Request Entity Too Large",
            414 => "Request-URI Too Long",
            415 => "Unsupported Media Type",
            416 => "Requested Range Not Satisfiable",
            417 => "Expectation Failed",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            505 => "HTTP Version Not Supported",
            _ => return None,
        })
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

//////////////////////////////////////////////////////////////////////////////
// Headers
//////////////////////////////////////////////////////////////////////////////

/// A case-insensitive, order-preserving map of header fields.
#[derive(Clone, Debug, Default)]
pub struct Headers {
    entries: Vec<(String, String)>,
}

impl Headers {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Append a field.  Multiple fields with the same name are allowed
    /// per RFC 2616 §4.2.
    pub fn append<N: Into<String>, V: Into<String>>(
        &mut self,
        name: N,
        value: V,
    ) {
        self.entries.push((name.into(), value.into()));
    }

    /// Remove any existing fields with the given name, then append one.
    pub fn set<N: Into<String>, V: Into<String>>(&mut self, name: N, value: V) {
        let name = name.into();
        self.entries.retain(|(n, _)| !ascii_eq(n, &name));
        self.entries.push((name, value.into()));
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(n, _)| ascii_eq(n, name))
            .map(|(_, v)| v.as_str())
    }

    pub fn get_all<'a>(
        &'a self,
        name: &'a str,
    ) -> impl Iterator<Item = &'a str> {
        self.entries
            .iter()
            .filter(move |(n, _)| ascii_eq(n, name))
            .map(|(_, v)| v.as_str())
    }

    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub fn remove(&mut self, name: &str) {
        self.entries.retain(|(n, _)| !ascii_eq(n, name));
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(n, v)| (n.as_str(), v.as_str()))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn ascii_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .all(|(x, y)| x.eq_ignore_ascii_case(&y))
}

//////////////////////////////////////////////////////////////////////////////
// Low-level parsing primitives
//////////////////////////////////////////////////////////////////////////////

const fn is_token(b: u8) -> bool {
    // RFC 2616 §2.2: token = 1*<any CHAR except CTLs or separators>.
    matches!(
        b,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'0'..=b'9'
            | b'A'..=b'Z'
            | b'^'
            | b'_'
            | b'`'
            | b'a'..=b'z'
            | b'|'
            | b'~'
    )
}

struct Parser<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    fn err<T>(&self, msg: &'static str) -> Result<T> {
        Err(Error::at(msg, self.pos))
    }

    fn expect(&mut self, bytes: &[u8]) -> Result<()> {
        if self.buf[self.pos..].starts_with(bytes) {
            self.pos += bytes.len();
            Ok(())
        } else {
            self.err("expected literal")
        }
    }

    fn expect_sp(&mut self) -> Result<()> {
        match self.peek() {
            Some(b' ') => {
                self.pos += 1;
                Ok(())
            }
            _ => self.err("expected SP"),
        }
    }

    /// Consume CRLF, or a bare LF per RFC 2616 §19.3 robustness.
    fn eat_crlf(&mut self) -> Result<()> {
        match self.peek() {
            Some(b'\r') if self.buf.get(self.pos + 1) == Some(&b'\n') => {
                self.pos += 2;
                Ok(())
            }
            Some(b'\n') => {
                self.pos += 1;
                Ok(())
            }
            _ => self.err("expected CRLF"),
        }
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ') | Some(b'\t')) {
            self.pos += 1;
        }
    }

    fn take_token(&mut self) -> Result<&'a [u8]> {
        let start = self.pos;
        while let Some(b) = self.peek() {
            if !is_token(b) {
                break;
            }
            self.pos += 1;
        }
        if self.pos == start {
            return self.err("expected token");
        }
        Ok(&self.buf[start..self.pos])
    }

    fn take_until_ws(&mut self) -> Result<&'a [u8]> {
        let start = self.pos;
        while let Some(b) = self.peek() {
            if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
                break;
            }
            self.pos += 1;
        }
        if self.pos == start {
            return self.err("expected non-whitespace");
        }
        Ok(&self.buf[start..self.pos])
    }

    fn take_until_eol(&mut self) -> &'a [u8] {
        let start = self.pos;
        while let Some(b) = self.peek() {
            if b == b'\r' || b == b'\n' {
                break;
            }
            self.pos += 1;
        }
        &self.buf[start..self.pos]
    }
}

fn parse_version(p: &mut Parser<'_>) -> Result<Version> {
    p.expect(b"HTTP/")?;
    let maj = parse_u16(p)?;
    p.expect(b".")?;
    let min = parse_u16(p)?;
    match (maj, min) {
        (1, 0) => Ok(Version::Http10),
        (1, 1) => Ok(Version::Http11),
        _ => p.err("unsupported HTTP version"),
    }
}

fn parse_u16(p: &mut Parser<'_>) -> Result<u16> {
    let start = p.pos;
    let mut n: u32 = 0;
    while let Some(b) = p.peek() {
        if !b.is_ascii_digit() {
            break;
        }
        n = n * 10 + (b - b'0') as u32;
        if n > u16::MAX as u32 {
            return p.err("numeric overflow");
        }
        p.pos += 1;
    }
    if p.pos == start {
        return p.err("expected digit");
    }
    Ok(n as u16)
}

fn parse_status_code(p: &mut Parser<'_>) -> Result<u16> {
    let mut d = [0u16; 3];
    for slot in &mut d {
        match p.peek() {
            Some(b) if b.is_ascii_digit() => {
                *slot = (b - b'0') as u16;
                p.pos += 1;
            }
            _ => return p.err("expected 3-digit status code"),
        }
    }
    Ok(d[0] * 100 + d[1] * 10 + d[2])
}

fn parse_headers(p: &mut Parser<'_>) -> Result<Headers> {
    let mut headers = Headers::new();
    loop {
        if matches!(p.peek(), Some(b'\r') | Some(b'\n')) {
            p.eat_crlf()?;
            return Ok(headers);
        }
        let name = p.take_token()?;
        let name = str::from_utf8(name)
            .expect("field-name is ASCII")
            .to_owned();

        if p.peek() != Some(b':') {
            return p.err("expected ':' after field-name");
        }
        p.pos += 1;
        p.skip_ws();

        let mut value = p.take_until_eol().to_vec();
        p.eat_crlf()?;

        // obs-fold: continuation lines begin with SP or HT.
        while matches!(p.peek(), Some(b' ') | Some(b'\t')) {
            p.skip_ws();
            let cont = p.take_until_eol();
            if !value.is_empty() && !cont.is_empty() {
                value.push(b' ');
            }
            value.extend_from_slice(cont);
            p.eat_crlf()?;
        }

        while matches!(value.last(), Some(b' ') | Some(b'\t')) {
            value.pop();
        }

        let value = String::from_utf8(value)
            .map_err(|_| Error::at("invalid UTF-8 in field-value", p.pos))?;
        headers.append(name, value);
    }
}

/// Parse an HTTP request head (request-line + header block terminated
/// by an empty line).  Returns the decoded request and the number of
/// bytes consumed.  RFC 2616 §5.
pub fn parse_request(buf: &[u8]) -> Result<(Request, usize)> {
    let mut p = Parser::new(buf);

    let method = Method::from_bytes(p.take_token()?);
    p.expect_sp()?;

    let target = p.take_until_ws()?;
    let target = str::from_utf8(target)
        .map_err(|_| Error::at("invalid UTF-8 in request-target", p.pos))?
        .to_owned();
    p.expect_sp()?;

    let version = parse_version(&mut p)?;
    p.eat_crlf()?;

    let headers = parse_headers(&mut p)?;
    Ok((
        Request {
            method,
            target,
            version,
            headers,
        },
        p.pos,
    ))
}

/// Parse an HTTP response head (status-line + header block).
pub fn parse_response_head(buf: &[u8]) -> Result<(ResponseHead, usize)> {
    let mut p = Parser::new(buf);

    let version = parse_version(&mut p)?;
    p.expect_sp()?;

    let code = parse_status_code(&mut p)?;
    p.expect_sp()?;

    let reason = p.take_until_eol();
    let reason = str::from_utf8(reason)
        .map_err(|_| Error::at("invalid UTF-8 in reason-phrase", p.pos))?
        .trim()
        .to_owned();
    p.eat_crlf()?;

    let headers = parse_headers(&mut p)?;
    Ok((
        ResponseHead {
            version,
            status: Status(code),
            reason,
            headers,
        },
        p.pos,
    ))
}

/// Read an HTTP message head (everything up to and including the empty
/// line separating the body).  The BufReader is positioned at the first
/// body byte on return.
fn read_head<R: BufRead>(r: &mut R) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(2048);
    loop {
        let start = buf.len();
        let n = r.read_until(b'\n', &mut buf)?;
        if n == 0 {
            return Err(Error::new("unexpected EOF reading head"));
        }
        if buf.len() > MAX_HEAD_BYTES {
            return Err(Error::new("head too large"));
        }
        let line = &buf[start..];
        if line == b"\r\n" || line == b"\n" {
            return Ok(buf);
        }
    }
}

//////////////////////////////////////////////////////////////////////////////
// Request (data) and ResponseHead
//////////////////////////////////////////////////////////////////////////////

/// A parsed HTTP request message head.
#[derive(Clone, Debug)]
pub struct Request {
    pub method: Method,
    pub target: String,
    pub version: Version,
    pub headers: Headers,
}

impl Request {
    /// Serialize the request-line + headers to `w`.  The caller writes
    /// any body bytes separately.
    pub fn write_head(&self, w: &mut impl Write) -> io::Result<()> {
        write!(w, "{} {} {}\r\n", self.method, self.target, self.version)?;
        write_headers(w, &self.headers)
    }
}

/// A parsed HTTP response message head.
#[derive(Clone, Debug)]
pub struct ResponseHead {
    pub version: Version,
    pub status: Status,
    pub reason: String,
    pub headers: Headers,
}

impl ResponseHead {
    pub fn write_head(&self, w: &mut impl Write) -> io::Result<()> {
        write!(w, "{} {} {}\r\n", self.version, self.status, self.reason)?;
        write_headers(w, &self.headers)
    }
}

fn write_headers(w: &mut impl Write, h: &Headers) -> io::Result<()> {
    for (name, value) in h.iter() {
        write!(w, "{}: {}\r\n", name, value)?;
    }
    w.write_all(b"\r\n")
}

//////////////////////////////////////////////////////////////////////////////
// Body framing (RFC 2616 §4.4)
//////////////////////////////////////////////////////////////////////////////

/// Framing rule for a message body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyLength {
    /// No body — 1xx/204/304 responses, or response to HEAD, or a
    /// request without Content-Length or Transfer-Encoding.
    Empty,
    /// Body of exactly N bytes (Content-Length).
    Fixed(u64),
    /// Chunked transfer-coding (RFC 2616 §3.6.1).
    Chunked,
    /// Body delimited by connection close (responses only).
    CloseDelimited,
}

/// Determine the framing for a response body given the request method,
/// response status, and response headers.  RFC 2616 §4.4.
pub fn response_body_length(
    request_method: &Method,
    status: Status,
    headers: &Headers,
) -> Result<BodyLength> {
    if *request_method == Method::Head
        || status.is_informational()
        || status.0 == 204
        || status.0 == 304
    {
        return Ok(BodyLength::Empty);
    }
    body_length_from_headers(headers, false)
}

/// Determine the framing for a request body given request headers.
pub fn request_body_length(headers: &Headers) -> Result<BodyLength> {
    body_length_from_headers(headers, true)
}

fn body_length_from_headers(
    headers: &Headers,
    is_request: bool,
) -> Result<BodyLength> {
    if let Some(te) = headers.get("Transfer-Encoding") {
        if is_final_chunked(te) {
            return Ok(BodyLength::Chunked);
        }
        return Err(Error::new("unsupported Transfer-Encoding"));
    }
    if let Some(cl) = headers.get("Content-Length") {
        let n: u64 = cl
            .trim()
            .parse()
            .map_err(|_| Error::new("invalid Content-Length"))?;
        return Ok(BodyLength::Fixed(n));
    }
    if is_request {
        Ok(BodyLength::Empty)
    } else {
        Ok(BodyLength::CloseDelimited)
    }
}

fn is_final_chunked(te: &str) -> bool {
    te.rsplit(',')
        .next()
        .map(|s| s.trim().eq_ignore_ascii_case("chunked"))
        .unwrap_or(false)
}

//////////////////////////////////////////////////////////////////////////////
// Chunked transfer-coding (RFC 2616 §3.6.1)
//////////////////////////////////////////////////////////////////////////////

/// A `Read` adapter that decodes chunked transfer-coding.
pub struct ChunkedReader<R: BufRead> {
    inner: R,
    state: ChunkState,
}

enum ChunkState {
    /// Next byte starts a chunk-size line.
    Size,
    /// Currently inside a chunk body; N bytes remain.
    Body(u64),
    /// Chunk body exhausted; consume trailing CRLF before next size.
    Tail,
    /// Zero-length chunk seen; trailer consumed; stream at EOF.
    Done,
}

impl<R: BufRead> ChunkedReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            state: ChunkState::Size,
        }
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: BufRead> Read for ChunkedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match &mut self.state {
                ChunkState::Done => return Ok(0),
                ChunkState::Tail => {
                    read_crlf(&mut self.inner)?;
                    self.state = ChunkState::Size;
                }
                ChunkState::Size => {
                    let size = read_chunk_size(&mut self.inner)?;
                    if size == 0 {
                        read_trailer(&mut self.inner)?;
                        self.state = ChunkState::Done;
                        return Ok(0);
                    }
                    self.state = ChunkState::Body(size);
                }
                ChunkState::Body(remaining) => {
                    if buf.is_empty() {
                        return Ok(0);
                    }
                    let want = buf.len().min(*remaining as usize);
                    let n = self.inner.read(&mut buf[..want])?;
                    if n == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "chunk truncated",
                        ));
                    }
                    *remaining -= n as u64;
                    if *remaining == 0 {
                        self.state = ChunkState::Tail;
                    }
                    return Ok(n);
                }
            }
        }
    }
}

fn read_chunk_size<R: BufRead>(r: &mut R) -> io::Result<u64> {
    let line = read_line_vec(r)?;
    let end = line.iter().position(|&b| b == b';').unwrap_or(line.len());
    let hex = str::from_utf8(&line[..end])
        .map_err(|_| invalid("non-ASCII chunk size"))?
        .trim();
    u64::from_str_radix(hex, 16).map_err(|_| invalid("invalid chunk size"))
}

fn read_trailer<R: BufRead>(r: &mut R) -> io::Result<()> {
    loop {
        let line = read_line_vec(r)?;
        if line.is_empty() {
            return Ok(());
        }
    }
}

fn read_crlf<R: BufRead>(r: &mut R) -> io::Result<()> {
    let line = read_line_vec(r)?;
    if line.is_empty() {
        Ok(())
    } else {
        Err(invalid("expected CRLF"))
    }
}

fn read_line_vec<R: BufRead>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let n = r.read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "unexpected EOF",
        ));
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    Ok(buf)
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// A `Write` adapter that encodes output in chunked transfer-coding.
/// Call [`finish`](Self::finish) to emit the terminating zero-chunk;
/// dropping without calling `finish` leaves the stream incomplete.
pub struct ChunkedWriter<W: Write> {
    inner: W,
}

impl<W: Write> ChunkedWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner }
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.inner.write_all(b"0\r\n\r\n")?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for ChunkedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        write!(self.inner, "{:x}\r\n", buf.len())?;
        self.inner.write_all(buf)?;
        self.inner.write_all(b"\r\n")?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

//////////////////////////////////////////////////////////////////////////////
// URL parsing (internal)
//////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scheme {
    Http,
    Https,
}

fn parse_url(url: &str) -> Result<(Scheme, &str, u16, &str)> {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
        (Scheme::Https, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (Scheme::Http, r)
    } else {
        return Err(Error::new("URL must start with http:// or https://"));
    };

    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };

    if authority.is_empty() {
        return Err(Error::new("URL missing host"));
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 =
                p.parse().map_err(|_| Error::new("invalid port in URL"))?;
            (h, port)
        }
        None => (
            authority,
            match scheme {
                Scheme::Http => 80,
                Scheme::Https => 443,
            },
        ),
    };

    Ok((scheme, host, port, path))
}

//////////////////////////////////////////////////////////////////////////////
// libtls FFI
//////////////////////////////////////////////////////////////////////////////

mod ffi {
    use std::os::raw::{c_char, c_int, c_void};

    #[repr(C)]
    pub struct Tls {
        _p: [u8; 0],
    }
    #[repr(C)]
    pub struct TlsConfig {
        _p: [u8; 0],
    }

    pub const TLS_WANT_POLLIN: isize = -2;
    pub const TLS_WANT_POLLOUT: isize = -3;

    #[link(name = "tls")]
    unsafe extern "C" {
        pub fn tls_init() -> c_int;
        pub fn tls_config_new() -> *mut TlsConfig;
        pub fn tls_config_free(c: *mut TlsConfig);
        pub fn tls_client() -> *mut Tls;
        pub fn tls_configure(ctx: *mut Tls, cfg: *mut TlsConfig) -> c_int;
        pub fn tls_connect_socket(
            ctx: *mut Tls,
            fd: c_int,
            servername: *const c_char,
        ) -> c_int;
        pub fn tls_handshake(ctx: *mut Tls) -> c_int;
        pub fn tls_write(ctx: *mut Tls, buf: *const c_void, n: usize) -> isize;
        pub fn tls_read(ctx: *mut Tls, buf: *mut c_void, n: usize) -> isize;
        pub fn tls_close(ctx: *mut Tls) -> c_int;
        pub fn tls_free(ctx: *mut Tls);
        pub fn tls_error(ctx: *mut Tls) -> *const c_char;
    }
}

struct TlsStream {
    ctx: *mut ffi::Tls,
    cfg: *mut ffi::TlsConfig,
    _sock: TcpStream,
}

impl TlsStream {
    fn connect(host: &str, sock: TcpStream) -> Result<Self> {
        unsafe {
            if ffi::tls_init() != 0 {
                return Err(Error::new("tls_init failed"));
            }
            let cfg = ffi::tls_config_new();
            if cfg.is_null() {
                return Err(Error::new("tls_config_new failed"));
            }
            let ctx = ffi::tls_client();
            if ctx.is_null() {
                ffi::tls_config_free(cfg);
                return Err(Error::new("tls_client failed"));
            }
            if ffi::tls_configure(ctx, cfg) != 0 {
                let e = tls_errmsg(ctx);
                ffi::tls_free(ctx);
                ffi::tls_config_free(cfg);
                return Err(Error::new(format!("tls_configure: {e}")));
            }
            let chost = CString::new(host)
                .map_err(|_| Error::new("host contains NUL"))?;
            if ffi::tls_connect_socket(ctx, sock.as_raw_fd(), chost.as_ptr())
                != 0
            {
                let e = tls_errmsg(ctx);
                ffi::tls_free(ctx);
                ffi::tls_config_free(cfg);
                return Err(Error::new(format!("tls_connect_socket: {e}")));
            }
            loop {
                let r = ffi::tls_handshake(ctx) as isize;
                if r == 0 {
                    break;
                }
                if r == ffi::TLS_WANT_POLLIN || r == ffi::TLS_WANT_POLLOUT {
                    continue;
                }
                let e = tls_errmsg(ctx);
                ffi::tls_free(ctx);
                ffi::tls_config_free(cfg);
                return Err(Error::new(format!("tls_handshake: {e}")));
            }
            Ok(Self {
                ctx,
                cfg,
                _sock: sock,
            })
        }
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            loop {
                let r = ffi::tls_read(
                    self.ctx,
                    buf.as_mut_ptr() as *mut c_void,
                    buf.len(),
                );
                if r == ffi::TLS_WANT_POLLIN || r == ffi::TLS_WANT_POLLOUT {
                    continue;
                }
                if r < 0 {
                    return Err(io::Error::other(format!(
                        "tls_read: {}",
                        tls_errmsg(self.ctx)
                    )));
                }
                return Ok(r as usize);
            }
        }
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            loop {
                let r = ffi::tls_write(
                    self.ctx,
                    buf.as_ptr() as *const c_void,
                    buf.len(),
                );
                if r == ffi::TLS_WANT_POLLIN || r == ffi::TLS_WANT_POLLOUT {
                    continue;
                }
                if r < 0 {
                    return Err(io::Error::other(format!(
                        "tls_write: {}",
                        tls_errmsg(self.ctx)
                    )));
                }
                return Ok(r as usize);
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for TlsStream {
    fn drop(&mut self) {
        unsafe {
            if !self.ctx.is_null() {
                loop {
                    let r = ffi::tls_close(self.ctx) as isize;
                    if r == 0
                        || (r != ffi::TLS_WANT_POLLIN
                            && r != ffi::TLS_WANT_POLLOUT)
                    {
                        break;
                    }
                }
                ffi::tls_free(self.ctx);
            }
            if !self.cfg.is_null() {
                ffi::tls_config_free(self.cfg);
            }
        }
    }
}

unsafe fn tls_errmsg(ctx: *mut ffi::Tls) -> String {
    unsafe {
        let p = ffi::tls_error(ctx);
        if p.is_null() {
            "(unknown)".into()
        } else {
            CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    }
}

//////////////////////////////////////////////////////////////////////////////
// Unified plain/TLS stream
//////////////////////////////////////////////////////////////////////////////

enum Stream {
    Plain(TcpStream),
    Tls(TlsStream),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(buf),
            Self::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(buf),
            Self::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            Self::Tls(s) => s.flush(),
        }
    }
}

fn connect(
    scheme: Scheme,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<Stream> {
    let sock = TcpStream::connect((host, port))
        .map_err(|e| Error::new(format!("connect {host}:{port}: {e}")))?;
    let _ = sock.set_read_timeout(Some(timeout));
    let _ = sock.set_write_timeout(Some(timeout));
    match scheme {
        Scheme::Http => Ok(Stream::Plain(sock)),
        Scheme::Https => Ok(Stream::Tls(TlsStream::connect(host, sock)?)),
    }
}

//////////////////////////////////////////////////////////////////////////////
// Response
//////////////////////////////////////////////////////////////////////////////

/// A response from a completed HTTP request.  The body is exposed as a
/// `Read` implementation so large or streaming responses (for example
/// Server-Sent Events) can be consumed incrementally.
pub struct Response {
    pub status: Status,
    pub version: Version,
    pub reason: String,
    pub headers: Headers,
    body: Body,
}

enum Body {
    Empty,
    Fixed(Take<BufReader<Stream>>),
    Chunked(ChunkedReader<BufReader<Stream>>),
    Close(BufReader<Stream>),
}

impl Response {
    /// Read the entire body into a `Vec<u8>`.
    pub fn body_bytes(mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.read_to_end(&mut out)?;
        Ok(out)
    }

    /// Read the entire body into a `String`, expecting valid UTF-8.
    pub fn body_string(mut self) -> Result<String> {
        let mut s = String::new();
        self.read_to_string(&mut s)?;
        Ok(s)
    }
}

impl Read for Response {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.body {
            Body::Empty => Ok(0),
            Body::Fixed(r) => r.read(buf),
            Body::Chunked(r) => r.read(buf),
            Body::Close(r) => r.read(buf),
        }
    }
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("version", &self.version)
            .field("reason", &self.reason)
            .field("headers", &self.headers)
            .finish()
    }
}

//////////////////////////////////////////////////////////////////////////////
// Request builder
//////////////////////////////////////////////////////////////////////////////

/// Fluent builder for outgoing requests.  Construct one via
/// [`get`], [`post`], [`put`], [`delete`], [`head`] or [`request`].
pub struct RequestBuilder {
    method: Method,
    url: String,
    headers: Headers,
    body: Vec<u8>,
    timeout: Duration,
}

impl RequestBuilder {
    fn new(method: Method, url: impl Into<String>) -> Self {
        Self {
            method,
            url: url.into(),
            headers: Headers::new(),
            body: Vec::new(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        }
    }

    /// Append a header.  Multiple calls with the same name append
    /// multiple fields (RFC 2616 §4.2).
    pub fn header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.headers.append(name, value);
        self
    }

    /// Set the request body.  Overwrites any previous body.  The
    /// Content-Length header is set automatically on send unless the
    /// caller already set one.
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Set the body from a list of form pairs, URL-encoded, and set
    /// Content-Type to application/x-www-form-urlencoded.
    pub fn form(mut self, pairs: &[(&str, &str)]) -> Self {
        self.body = url_form(pairs).into_bytes();
        if !self.headers.contains("Content-Type") {
            self.headers
                .set("Content-Type", "application/x-www-form-urlencoded");
        }
        self
    }

    /// Set the body to a `multipart/form-data` payload (RFC 2388) and
    /// the Content-Type header (with boundary).  Overwrites any previous
    /// body and Content-Type.
    pub fn multipart(mut self, form: Multipart) -> Self {
        let ct = form.content_type();
        self.body = form.into_bytes();
        self.headers.set("Content-Type", ct);
        self
    }

    /// Override the read/write timeout.  Default is 30 seconds.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Send the request and return the response.  The underlying
    /// connection is closed when the response is dropped.
    pub fn send(mut self) -> Result<Response> {
        let (scheme, host, port, path) = parse_url(&self.url)?;

        if !self.headers.contains("Host") {
            let host_hdr = if (scheme == Scheme::Http && port == 80)
                || (scheme == Scheme::Https && port == 443)
            {
                host.to_string()
            } else {
                format!("{host}:{port}")
            };
            self.headers.set("Host", host_hdr);
        }
        if !self.headers.contains("User-Agent") {
            self.headers.set("User-Agent", format!("http/{VERSION}"));
        }
        if !self.headers.contains("Connection") {
            self.headers.set("Connection", "close");
        }
        if !self.body.is_empty() && !self.headers.contains("Content-Length") {
            self.headers
                .set("Content-Length", self.body.len().to_string());
        }

        let stream = connect(scheme, host, port, self.timeout)?;
        let mut stream = stream;

        write!(stream, "{} {} HTTP/1.1\r\n", self.method, path)?;
        for (name, value) in self.headers.iter() {
            write!(stream, "{}: {}\r\n", name, value)?;
        }
        stream.write_all(b"\r\n")?;
        if !self.body.is_empty() {
            stream.write_all(&self.body)?;
        }
        stream.flush()?;

        let mut reader = BufReader::new(stream);
        let head = read_head(&mut reader)?;
        let (h, _) = parse_response_head(&head)?;

        let length = response_body_length(&self.method, h.status, &h.headers)?;
        let body = match length {
            BodyLength::Empty => Body::Empty,
            BodyLength::Fixed(n) => Body::Fixed(reader.take(n)),
            BodyLength::Chunked => Body::Chunked(ChunkedReader::new(reader)),
            BodyLength::CloseDelimited => Body::Close(reader),
        };

        Ok(Response {
            status: h.status,
            version: h.version,
            reason: h.reason,
            headers: h.headers,
            body,
        })
    }
}

//////////////////////////////////////////////////////////////////////////////
// Top-level constructors
//////////////////////////////////////////////////////////////////////////////

pub fn get(url: impl Into<String>) -> RequestBuilder {
    RequestBuilder::new(Method::Get, url)
}

pub fn head(url: impl Into<String>) -> RequestBuilder {
    RequestBuilder::new(Method::Head, url)
}

pub fn post(url: impl Into<String>) -> RequestBuilder {
    RequestBuilder::new(Method::Post, url)
}

pub fn put(url: impl Into<String>) -> RequestBuilder {
    RequestBuilder::new(Method::Put, url)
}

pub fn delete(url: impl Into<String>) -> RequestBuilder {
    RequestBuilder::new(Method::Delete, url)
}

pub fn patch(url: impl Into<String>) -> RequestBuilder {
    RequestBuilder::new(Method::Patch, url)
}

pub fn request(method: Method, url: impl Into<String>) -> RequestBuilder {
    RequestBuilder::new(method, url)
}

//////////////////////////////////////////////////////////////////////////////
// URL encoding utilities
//////////////////////////////////////////////////////////////////////////////

/// Percent-encode per RFC 3986 §2.3 (unreserved set).
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'.'
            | b'_'
            | b'~' => out.push(b as char),
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Percent-decode.  `+` is interpreted as space (form convention).
/// Invalid sequences are emitted literally.
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = str::from_utf8(&bytes[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                match hex {
                    Some(b) => {
                        out.push(b);
                        i += 3;
                    }
                    None => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

/// Serialize a list of key-value pairs as application/x-www-form-urlencoded.
pub fn url_form(pairs: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(&percent_encode(k));
        out.push('=');
        out.push_str(&percent_encode(v));
    }
    out
}

//////////////////////////////////////////////////////////////////////////////
// multipart/form-data (RFC 2388)
//////////////////////////////////////////////////////////////////////////////

/// A `multipart/form-data` body builder.  RFC 2388.
///
/// Each part has a name and either a text value or a file payload
/// (filename + content-type + bytes).  Pass the finished form to
/// [`RequestBuilder::multipart`], which sets the Content-Type header
/// (with the boundary) and serializes the body.
#[derive(Clone, Debug)]
pub struct Multipart {
    boundary: String,
    parts: Vec<Part>,
}

#[derive(Clone, Debug)]
struct Part {
    name: String,
    filename: Option<String>,
    content_type: Option<String>,
    body: Vec<u8>,
}

impl Multipart {
    /// Create a new form with a fresh boundary.
    pub fn new() -> Self {
        Self {
            boundary: gen_boundary(),
            parts: Vec::new(),
        }
    }

    /// Append a text field.
    pub fn text(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.parts.push(Part {
            name: name.into(),
            filename: None,
            content_type: None,
            body: value.into().into_bytes(),
        });
        self
    }

    /// Append a file field with explicit filename, content type, and bytes.
    pub fn file(
        mut self,
        name: impl Into<String>,
        filename: impl Into<String>,
        content_type: impl Into<String>,
        body: impl Into<Vec<u8>>,
    ) -> Self {
        self.parts.push(Part {
            name: name.into(),
            filename: Some(filename.into()),
            content_type: Some(content_type.into()),
            body: body.into(),
        });
        self
    }

    /// Append a file field by reading `path` from disk.  The filename
    /// sent is the path's final component.
    pub fn file_path(
        self,
        name: impl Into<String>,
        path: impl AsRef<std::path::Path>,
        content_type: impl Into<String>,
    ) -> Result<Self> {
        let path = path.as_ref();
        let body = std::fs::read(path)
            .map_err(|e| Error::new(format!("read {}: {e}", path.display())))?;
        let filename = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| Error::new("path has no file name"))?
            .to_owned();
        Ok(self.file(name, filename, content_type, body))
    }

    /// The boundary string (without the leading dashes).
    pub fn boundary(&self) -> &str {
        &self.boundary
    }

    /// Value to use in the `Content-Type` header.
    pub fn content_type(&self) -> String {
        format!("multipart/form-data; boundary={}", self.boundary)
    }

    /// Serialize the form body to bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_to(&mut out).expect("Vec write is infallible");
        out
    }

    /// Write the serialized form body to `w`.
    pub fn write_to(&self, w: &mut impl Write) -> io::Result<()> {
        for part in &self.parts {
            write!(w, "--{}\r\n", self.boundary)?;
            w.write_all(b"Content-Disposition: form-data; name=\"")?;
            write_quoted(w, &part.name)?;
            w.write_all(b"\"")?;
            if let Some(filename) = &part.filename {
                w.write_all(b"; filename=\"")?;
                write_quoted(w, filename)?;
                w.write_all(b"\"")?;
            }
            w.write_all(b"\r\n")?;
            if let Some(ct) = &part.content_type {
                write!(w, "Content-Type: {ct}\r\n")?;
            }
            w.write_all(b"\r\n")?;
            w.write_all(&part.body)?;
            w.write_all(b"\r\n")?;
        }
        write!(w, "--{}--\r\n", self.boundary)
    }
}

impl Default for Multipart {
    fn default() -> Self {
        Self::new()
    }
}

/// Backslash-escape `"` and `\` per RFC 2616 §2.2 quoted-string.  CR/LF
/// are not legal inside a quoted-string, so they are dropped.
fn write_quoted(w: &mut impl Write, s: &str) -> io::Result<()> {
    for &b in s.as_bytes() {
        match b {
            b'"' | b'\\' => w.write_all(&[b'\\', b])?,
            b'\r' | b'\n' => continue,
            _ => w.write_all(&[b])?,
        }
    }
    Ok(())
}

/// A boundary that is unique within a process: nanos + pid + counter,
/// as 70-bchar-safe hex.  RFC 2046 §5.1.1 only requires uniqueness
/// against the body, not unpredictability.
fn gen_boundary() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let pid = std::process::id() as u64;
    format!("----http-rs-{nanos:016x}-{pid:08x}-{n:08x}")
}

//////////////////////////////////////////////////////////////////////////////
// Tests
//////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn method_round_trip() {
        for m in [
            Method::Get,
            Method::Head,
            Method::Post,
            Method::Put,
            Method::Delete,
            Method::Options,
            Method::Trace,
            Method::Connect,
            Method::Patch,
        ] {
            assert_eq!(Method::from_bytes(m.as_str().as_bytes()), m);
        }
    }

    #[test]
    fn method_extension() {
        let m = Method::from_bytes(b"FOO");
        assert_eq!(m, Method::Other("FOO".into()));
        assert_eq!(m.as_str(), "FOO");
    }

    #[test]
    fn status_classes() {
        assert!(Status(100).is_informational());
        assert!(Status(204).is_success());
        assert!(Status(301).is_redirection());
        assert!(Status(404).is_client_error());
        assert!(Status(500).is_server_error());
    }

    #[test]
    fn status_reasons() {
        assert_eq!(Status(200).canonical_reason(), Some("OK"));
        assert_eq!(Status(404).canonical_reason(), Some("Not Found"));
        assert_eq!(Status(599).canonical_reason(), None);
    }

    #[test]
    fn headers_case_insensitive() {
        let mut h = Headers::new();
        h.append("Content-Type", "text/plain");
        assert_eq!(h.get("content-type"), Some("text/plain"));
        assert_eq!(h.get("CONTENT-TYPE"), Some("text/plain"));
    }

    #[test]
    fn headers_set_replaces() {
        let mut h = Headers::new();
        h.append("X", "1");
        h.append("x", "2");
        h.set("X", "3");
        assert_eq!(h.get("X"), Some("3"));
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn headers_multi_value() {
        let mut h = Headers::new();
        h.append("Set-Cookie", "a=1");
        h.append("Set-Cookie", "b=2");
        let all: Vec<&str> = h.get_all("set-cookie").collect();
        assert_eq!(all, vec!["a=1", "b=2"]);
    }

    #[test]
    fn parse_request_simple() {
        let input = b"GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (r, n) = parse_request(input).unwrap();
        assert_eq!(r.method, Method::Get);
        assert_eq!(r.target, "/foo");
        assert_eq!(r.version, Version::Http11);
        assert_eq!(r.headers.get("Host"), Some("example.com"));
        assert_eq!(n, input.len());
    }

    #[test]
    fn parse_request_bare_lf() {
        // RFC 2616 §19.3 robustness: accept bare LF line endings.
        let input = b"GET / HTTP/1.0\nHost: example.com\n\n";
        let (r, _) = parse_request(input).unwrap();
        assert_eq!(r.method, Method::Get);
        assert_eq!(r.version, Version::Http10);
    }

    #[test]
    fn parse_request_extension_method() {
        let input = b"FOO / HTTP/1.1\r\n\r\n";
        let (r, _) = parse_request(input).unwrap();
        assert_eq!(r.method, Method::Other("FOO".into()));
    }

    #[test]
    fn parse_response_simple() {
        let input = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
        let (h, n) = parse_response_head(input).unwrap();
        assert_eq!(h.status, Status(200));
        assert_eq!(h.version, Version::Http11);
        assert_eq!(h.reason, "OK");
        assert_eq!(h.headers.get("Content-Length"), Some("5"));
        assert_eq!(n, input.len());
    }

    #[test]
    fn parse_response_multiword_reason() {
        let input = b"HTTP/1.1 404 Not Found\r\n\r\n";
        let (h, _) = parse_response_head(input).unwrap();
        assert_eq!(h.status, Status(404));
        assert_eq!(h.reason, "Not Found");
    }

    #[test]
    fn parse_obs_fold() {
        // RFC 2616 §2.2 obs-fold: header value continuation.
        let input =
            b"GET / HTTP/1.1\r\nX-Long: one\r\n  two\r\n\tthree\r\n\r\n";
        let (r, _) = parse_request(input).unwrap();
        assert_eq!(r.headers.get("X-Long"), Some("one two three"));
    }

    #[test]
    fn parse_rejects_bad_version() {
        let input = b"GET / HTTP/9.9\r\n\r\n";
        assert!(parse_request(input).is_err());
    }

    #[test]
    fn parse_rejects_missing_colon() {
        let input = b"GET / HTTP/1.1\r\nBadHeader\r\n\r\n";
        assert!(parse_request(input).is_err());
    }

    #[test]
    fn body_length_head_is_empty() {
        let h = Headers::new();
        let r = response_body_length(&Method::Head, Status(200), &h).unwrap();
        assert_eq!(r, BodyLength::Empty);
    }

    #[test]
    fn body_length_204_is_empty() {
        let mut h = Headers::new();
        h.set("Content-Length", "42");
        let r = response_body_length(&Method::Get, Status(204), &h).unwrap();
        assert_eq!(r, BodyLength::Empty);
    }

    #[test]
    fn body_length_chunked() {
        let mut h = Headers::new();
        h.set("Transfer-Encoding", "chunked");
        let r = response_body_length(&Method::Get, Status(200), &h).unwrap();
        assert_eq!(r, BodyLength::Chunked);
    }

    #[test]
    fn body_length_chunked_wins_over_content_length() {
        let mut h = Headers::new();
        h.set("Transfer-Encoding", "chunked");
        h.set("Content-Length", "10");
        let r = response_body_length(&Method::Get, Status(200), &h).unwrap();
        assert_eq!(r, BodyLength::Chunked);
    }

    #[test]
    fn body_length_close_delimited_default() {
        let h = Headers::new();
        let r = response_body_length(&Method::Get, Status(200), &h).unwrap();
        assert_eq!(r, BodyLength::CloseDelimited);
    }

    #[test]
    fn body_length_request_no_body_default() {
        let h = Headers::new();
        let r = request_body_length(&h).unwrap();
        assert_eq!(r, BodyLength::Empty);
    }

    #[test]
    fn chunked_decode() {
        // RFC 2616 §3.6.1 example.
        let input =
            b"4\r\nWiki\r\n5\r\npedia\r\ne\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n";
        let mut r = ChunkedReader::new(Cursor::new(&input[..]));
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"Wikipedia in\r\n\r\nchunks.");
    }

    #[test]
    fn chunked_decode_with_trailer() {
        let input = b"5\r\nhello\r\n0\r\nX-Trailer: v\r\n\r\n";
        let mut r = ChunkedReader::new(Cursor::new(&input[..]));
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"hello");
    }

    #[test]
    fn chunked_decode_with_extension() {
        let input = b"5;name=foo\r\nhello\r\n0\r\n\r\n";
        let mut r = ChunkedReader::new(Cursor::new(&input[..]));
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"hello");
    }

    #[test]
    fn chunked_round_trip() {
        let mut buf = Vec::new();
        {
            let mut w = ChunkedWriter::new(&mut buf);
            w.write_all(b"Hello, ").unwrap();
            w.write_all(b"world!").unwrap();
            w.finish().unwrap();
        }
        let mut r = ChunkedReader::new(Cursor::new(&buf));
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"Hello, world!");
    }

    #[test]
    fn request_write_head() {
        let req = Request {
            method: Method::Post,
            target: "/x".into(),
            version: Version::Http11,
            headers: {
                let mut h = Headers::new();
                h.set("Host", "example.com");
                h
            },
        };
        let mut buf = Vec::new();
        req.write_head(&mut buf).unwrap();
        assert_eq!(buf, b"POST /x HTTP/1.1\r\nHost: example.com\r\n\r\n");
    }

    #[test]
    fn percent_encode_basic() {
        assert_eq!(percent_encode("a b+c"), "a%20b%2Bc");
        assert_eq!(percent_encode("~-._"), "~-._");
    }

    #[test]
    fn percent_decode_basic() {
        assert_eq!(percent_decode("a%20b%2Bc"), "a b+c");
        assert_eq!(percent_decode("a+b"), "a b");
    }

    #[test]
    fn url_form_encoding() {
        let s = url_form(&[("k1", "v 1"), ("k2", "a&b")]);
        assert_eq!(s, "k1=v%201&k2=a%26b");
    }

    #[test]
    fn parse_url_defaults() {
        let (s, h, p, path) = parse_url("https://example.com/").unwrap();
        assert_eq!(s, Scheme::Https);
        assert_eq!(h, "example.com");
        assert_eq!(p, 443);
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_url_with_port_and_path() {
        let (s, h, p, path) =
            parse_url("http://localhost:8080/api?x=1").unwrap();
        assert_eq!(s, Scheme::Http);
        assert_eq!(h, "localhost");
        assert_eq!(p, 8080);
        assert_eq!(path, "/api?x=1");
    }

    #[test]
    fn parse_url_missing_path() {
        let (_, _, _, path) = parse_url("http://example.com").unwrap();
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_url_rejects_bad_scheme() {
        assert!(parse_url("ftp://example.com/").is_err());
    }

    #[test]
    fn final_chunked_detection() {
        assert!(is_final_chunked("chunked"));
        assert!(is_final_chunked("gzip, chunked"));
        assert!(is_final_chunked("  chunked  "));
        assert!(!is_final_chunked("chunked, gzip"));
        assert!(!is_final_chunked("gzip"));
    }

    #[test]
    fn multipart_format() {
        let form = Multipart::new().text("name", "Murilo").file(
            "upload",
            "hello.txt",
            "text/plain",
            b"hello".to_vec(),
        );
        let boundary = form.boundary().to_owned();
        let s = String::from_utf8(form.into_bytes()).unwrap();
        let expected = format!(
            "--{b}\r\n\
             Content-Disposition: form-data; name=\"name\"\r\n\
             \r\n\
             Murilo\r\n\
             --{b}\r\n\
             Content-Disposition: form-data; name=\"upload\"; \
             filename=\"hello.txt\"\r\n\
             Content-Type: text/plain\r\n\
             \r\n\
             hello\r\n\
             --{b}--\r\n",
            b = boundary,
        );
        assert_eq!(s, expected);
    }

    #[test]
    fn multipart_content_type_header() {
        let form = Multipart::new();
        let ct = form.content_type();
        let prefix = "multipart/form-data; boundary=";
        assert!(ct.starts_with(prefix));
        assert_eq!(&ct[prefix.len()..], form.boundary());
    }

    #[test]
    fn multipart_quotes_special_chars() {
        let form = Multipart::new().file(
            "f",
            "a\"b\\c.txt",
            "application/octet-stream",
            b"x".to_vec(),
        );
        let s = String::from_utf8(form.into_bytes()).unwrap();
        assert!(s.contains("filename=\"a\\\"b\\\\c.txt\""));
    }

    #[test]
    fn multipart_unique_boundaries() {
        let a = Multipart::new();
        let b = Multipart::new();
        assert_ne!(a.boundary(), b.boundary());
    }

    #[test]
    fn multipart_empty_form() {
        let form = Multipart::new();
        let boundary = form.boundary().to_owned();
        let s = String::from_utf8(form.into_bytes()).unwrap();
        assert_eq!(s, format!("--{boundary}--\r\n"));
    }
}
