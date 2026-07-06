//! Minimal HTTP/1.1 endpoint so a browser can POST the encrypted command
//! envelope straight to the device — no proxy in between.
//!
//! CORS (and the Private-Network-Access preflight) are answered permissively:
//! the command crypto (Ed25519 + roles + replay guard), not the request origin,
//! is what authorizes anything. The body is end-to-end encrypted, so plaintext
//! HTTP transport is fine.

use embassy_net::tcp::TcpSocket;

pub enum Request {
    /// A POST whose body is the crypto envelope (`ephemeral;iv;ciphertext`).
    Post(heapless::Vec<u8, 2048>),
    /// A CORS / PNA preflight (OPTIONS) to acknowledge.
    Preflight,
}

/// Read and parse one HTTP request. `None` on close / error / oversized / bad.
pub async fn read_request(socket: &mut TcpSocket<'_>, buf: &mut [u8]) -> Option<Request> {
    let mut req = heapless::Vec::<u8, 4096>::new();
    let mut header_end: Option<usize> = None;
    let mut content_length: usize = 0;

    loop {
        let n = match socket.read(buf).await {
            Ok(0) => return None,
            Ok(n) => n,
            Err(_) => return None,
        };
        if req.extend_from_slice(&buf[..n]).is_err() {
            return None; // request larger than we accept
        }

        if header_end.is_none() {
            if let Some(pos) = find(&req, b"\r\n\r\n") {
                let head = &req[..pos];
                if starts_with_ci(head, b"OPTIONS ") {
                    return Some(Request::Preflight);
                }
                header_end = Some(pos + 4);
                content_length = content_length_of(head);
            }
        }

        if let Some(he) = header_end {
            if req.len() >= he + content_length {
                let end = core::cmp::min(he + content_length, req.len());
                let mut body = heapless::Vec::<u8, 2048>::new();
                let _ = body.extend_from_slice(&req[he..end]);
                return Some(Request::Post(body));
            }
        }

        if req.is_full() {
            return None;
        }
    }
}

/// Send `body` as an HTTP/1.1 200 with permissive CORS.
pub async fn write_response(socket: &mut TcpSocket<'_>, body: &str) {
    use core::fmt::Write as _;
    let mut head = heapless::String::<256>::new();
    let _ = write!(
        &mut head,
        "HTTP/1.1 200 OK\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    write_all(socket, head.as_bytes()).await;
    write_all(socket, body.as_bytes()).await;
    let _ = socket.flush().await;
}

/// Acknowledge a CORS / Private-Network-Access preflight.
pub async fn write_preflight(socket: &mut TcpSocket<'_>) {
    let head = "HTTP/1.1 204 No Content\r\n\
                Access-Control-Allow-Origin: *\r\n\
                Access-Control-Allow-Methods: POST, OPTIONS\r\n\
                Access-Control-Allow-Headers: *\r\n\
                Access-Control-Allow-Private-Network: true\r\n\
                Content-Length: 0\r\n\
                Connection: close\r\n\r\n";
    write_all(socket, head.as_bytes()).await;
    let _ = socket.flush().await;
}

async fn write_all(socket: &mut TcpSocket<'_>, mut data: &[u8]) {
    while !data.is_empty() {
        match socket.write(data).await {
            Ok(0) | Err(_) => break,
            Ok(n) => data = &data[n..],
        }
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn starts_with_ci(hay: &[u8], prefix: &[u8]) -> bool {
    hay.len() >= prefix.len() && hay[..prefix.len()].eq_ignore_ascii_case(prefix)
}

fn content_length_of(head: &[u8]) -> usize {
    if let Ok(s) = core::str::from_utf8(head) {
        for line in s.split("\r\n") {
            if let Some((name, value)) = line.split_once(':') {
                if name.trim().eq_ignore_ascii_case("content-length") {
                    return value.trim().parse::<usize>().unwrap_or(0);
                }
            }
        }
    }
    0
}
