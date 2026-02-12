/// HTTP Mask 伪装层（Legacy 模式）
///
/// 在 Sudoku 混淆之前，写入一个伪 HTTP/1.1 请求头，
/// 使初始握手流量看起来像正常的 HTTP 请求。

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 写入随机 HTTP/1.1 请求头（客户端用）
pub async fn write_http_mask<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    host: &str,
    path_root: &str,
) -> std::io::Result<()> {
    let path = if path_root.is_empty() {
        random_path()
    } else {
        format!("/{}/{}", path_root.trim_matches('/'), random_segment())
    };

    let ua = random_user_agent();
    let header = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n",
        path, host, ua,
    );

    writer.write_all(header.as_bytes()).await
}

/// 检查数据开头是否像 HTTP 请求
pub fn looks_like_http_request(peek: &[u8]) -> bool {
    if peek.len() < 4 {
        return false;
    }
    peek.starts_with(b"GET ")
        || peek.starts_with(b"POST")
        || peek.starts_with(b"PUT ")
        || peek.starts_with(b"HEAD")
}

/// 消费 HTTP 请求头（服务端用）
pub async fn consume_http_header<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(1024);
    loop {
        let byte = reader.read_u8().await?;
        buf.push(byte);
        if buf.len() >= 4 && buf[buf.len() - 4..] == *b"\r\n\r\n" {
            return Ok(());
        }
        if buf.len() > 8192 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP header too long",
            ));
        }
    }
}

fn random_path() -> String {
    let segments = ["api", "cdn", "assets", "static", "media", "content", "data", "v1", "v2"];
    let mut rng = rand::thread_rng();
    let seg = segments[rand::Rng::gen_range(&mut rng, 0..segments.len())];
    format!("/{}/{}", seg, random_segment())
}

fn random_segment() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let len = rng.gen_range(8..16);
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..36u8);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'a' + idx - 10) as char
            }
        })
        .collect()
}

fn random_user_agent() -> &'static str {
    const UAS: &[&str] = &[
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    ];
    let mut rng = rand::thread_rng();
    UAS[rand::Rng::gen_range(&mut rng, 0..UAS.len())]
}
