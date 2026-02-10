/// 协议嗅探：从流的前几个字节检测目标域名
///
/// 支持：
/// - TLS ClientHello SNI 提取
/// - HTTP Host 头提取

/// 对原始数据进行嗅探，返回检测到的域名
pub fn sniff(data: &[u8]) -> Option<String> {
    // 优先尝试 TLS（更常见）
    if let Some(host) = parse_tls_sni(data) {
        return Some(host);
    }
    if let Some(host) = parse_http_host(data) {
        return Some(host);
    }
    None
}

/// 从 TLS ClientHello 中提取 SNI（Server Name Indication）
fn parse_tls_sni(data: &[u8]) -> Option<String> {
    // TLS record: [ContentType: 1B] [Version: 2B] [Length: 2B] [Fragment]
    if data.len() < 5 {
        return None;
    }

    // ContentType must be 0x16 (Handshake)
    if data[0] != 0x16 {
        return None;
    }

    // Version check (0x0300 - 0x0303)
    let version = u16::from_be_bytes([data[1], data[2]]);
    if !(0x0300..=0x0303).contains(&version) {
        return None;
    }

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    let fragment = data.get(5..5 + record_len)?;

    // Handshake: [Type: 1B] [Length: 3B] [Body]
    if fragment.is_empty() || fragment[0] != 0x01 {
        // Type must be 0x01 (ClientHello)
        return None;
    }

    if fragment.len() < 4 {
        return None;
    }

    let handshake_len =
        ((fragment[1] as usize) << 16) | ((fragment[2] as usize) << 8) | (fragment[3] as usize);
    let body = fragment.get(4..4 + handshake_len)?;

    // ClientHello body:
    // [Version: 2B] [Random: 32B] [SessionIDLen: 1B] [SessionID] ...
    if body.len() < 34 {
        return None;
    }

    let mut pos = 34; // skip version(2) + random(32)

    // Session ID
    let session_id_len = *body.get(pos)? as usize;
    pos += 1 + session_id_len;

    // Cipher Suites
    if pos + 2 > body.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    // Compression Methods
    if pos >= body.len() {
        return None;
    }
    let compression_len = body[pos] as usize;
    pos += 1 + compression_len;

    // Extensions
    if pos + 2 > body.len() {
        return None;
    }
    let extensions_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = pos + extensions_len;
    if extensions_end > body.len() {
        return None;
    }

    // 遍历 extensions 查找 SNI (type = 0x0000)
    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension
            return parse_sni_extension(body.get(pos..pos + ext_len)?);
        }

        pos += ext_len;
    }

    None
}

/// 解析 SNI extension 数据
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    // [ServerNameListLength: 2B] [entries...]
    if data.len() < 2 {
        return None;
    }

    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if list_len + 2 > data.len() {
        return None;
    }

    let mut pos = 2;
    let list_end = 2 + list_len;

    while pos + 3 <= list_end {
        let name_type = data[pos];
        let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
        pos += 3;

        if name_type == 0 {
            // host_name
            let name = data.get(pos..pos + name_len)?;
            return String::from_utf8(name.to_vec()).ok();
        }

        pos += name_len;
    }

    None
}

/// 从 HTTP 请求中提取 Host
fn parse_http_host(data: &[u8]) -> Option<String> {
    // 检查是否以 HTTP 方法开头
    let methods = [
        b"GET " as &[u8],
        b"POST ",
        b"PUT ",
        b"HEAD ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
        b"CONNECT ",
    ];

    let is_http = methods.iter().any(|m| data.starts_with(m));
    if !is_http {
        return None;
    }

    // 转为字符串搜索 Host 头
    let text = std::str::from_utf8(data).ok()?;

    for line in text.lines() {
        if let Some(host_value) = line.strip_prefix("Host:").or_else(|| line.strip_prefix("host:")) {
            let host = host_value.trim();
            // 去掉端口部分（如果有）
            let hostname = if let Some((h, _port)) = host.rsplit_once(':') {
                // 确认端口是数字
                if _port.chars().all(|c| c.is_ascii_digit()) {
                    h
                } else {
                    host
                }
            } else {
                host
            };
            if !hostname.is_empty() {
                return Some(hostname.to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_client_hello_sni() {
        // 构造一个最小的 TLS ClientHello with SNI
        let sni = b"example.com";
        let client_hello = build_test_client_hello(sni);
        let result = parse_tls_sni(&client_hello);
        assert_eq!(result, Some("example.com".to_string()));
    }

    #[test]
    fn tls_no_sni() {
        // 太短的数据
        assert_eq!(parse_tls_sni(&[0x16, 0x03, 0x01]), None);
    }

    #[test]
    fn tls_not_handshake() {
        // ContentType 不是 0x16
        assert_eq!(parse_tls_sni(&[0x17, 0x03, 0x01, 0x00, 0x01, 0x00]), None);
    }

    #[test]
    fn http_host_get() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        assert_eq!(parse_http_host(data), Some("example.com".to_string()));
    }

    #[test]
    fn http_host_with_port() {
        let data = b"GET /path HTTP/1.1\r\nHost: example.com:8080\r\nConnection: close\r\n\r\n";
        assert_eq!(parse_http_host(data), Some("example.com".to_string()));
    }

    #[test]
    fn http_host_post() {
        let data = b"POST /api HTTP/1.1\r\nhost: api.example.com\r\n\r\n";
        assert_eq!(parse_http_host(data), Some("api.example.com".to_string()));
    }

    #[test]
    fn http_not_http() {
        let data = b"\x16\x03\x01binary data";
        assert_eq!(parse_http_host(data), None);
    }

    #[test]
    fn sniff_tls_prefers_over_http() {
        let hello = build_test_client_hello(b"tls.example.com");
        assert_eq!(sniff(&hello), Some("tls.example.com".to_string()));
    }

    #[test]
    fn sniff_http_fallback() {
        let data = b"GET / HTTP/1.1\r\nHost: http.example.com\r\n\r\n";
        assert_eq!(sniff(data), Some("http.example.com".to_string()));
    }

    #[test]
    fn sniff_unknown() {
        assert_eq!(sniff(b"random binary data"), None);
    }

    /// 构造测试用的 TLS ClientHello（仅包含 SNI extension）
    fn build_test_client_hello(sni: &[u8]) -> Vec<u8> {
        // SNI extension data
        let mut sni_ext = Vec::new();
        // ServerNameList length
        let name_entry_len = 1 + 2 + sni.len(); // type(1) + length(2) + name
        sni_ext.extend_from_slice(&(name_entry_len as u16).to_be_bytes());
        sni_ext.push(0x00); // host_name type
        sni_ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(sni);

        // Extensions
        let mut extensions = Vec::new();
        // SNI extension: type=0x0000
        extensions.extend_from_slice(&[0x00, 0x00]); // extension type
        extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext);

        // ClientHello body
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // version TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0x00); // session ID length = 0
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]); // cipher suites (1 suite)
        body.push(0x01); // compression methods length
        body.push(0x00); // null compression
        // extensions
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        // Handshake
        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello type
        let body_len = body.len();
        handshake.push(((body_len >> 16) & 0xff) as u8);
        handshake.push(((body_len >> 8) & 0xff) as u8);
        handshake.push((body_len & 0xff) as u8);
        handshake.extend_from_slice(&body);

        // TLS Record
        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        record
    }
}
