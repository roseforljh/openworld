/// 协议嗅探：从流的前几个字节检测目标域名。
///
/// 支持：
/// - TLS ClientHello SNI 提取
/// - HTTP Host 头提取
/// - QUIC Initial 包 SNI 提取
///
/// 协议检测（无域名返回，用于分类路由）：
/// - BitTorrent 协议检测
/// - STUN 协议检测
/// - DTLS ClientHello 检测
///
/// 对原始数据进行嗅探，返回检测到的域名。
pub fn sniff(data: &[u8]) -> Option<String> {
    // 优先尝试 TLS（更常见）
    if let Some(host) = parse_tls_sni(data) {
        return Some(host);
    }
    if let Some(host) = parse_http_host(data) {
        return Some(host);
    }
    if let Some(host) = parse_quic_sni(data) {
        return Some(host);
    }
    None
}

/// 检测协议类型（不提取域名，仅识别协议种类）
pub fn detect_protocol(data: &[u8]) -> Option<&'static str> {
    // DTLS 必须在 TLS 之前检查（两者都以 0x16 开头，DTLS 版本为 0xFExx）
    if is_dtls(data) {
        return Some("dtls");
    }
    if data.len() >= 5 && data[0] == 0x16 {
        return Some("tls");
    }
    if is_http_request(data) {
        return Some("http");
    }
    if is_bittorrent(data) {
        return Some("bittorrent");
    }
    if is_stun(data) {
        return Some("stun");
    }
    if is_quic_initial(data) {
        return Some("quic");
    }
    if is_ssh(data) {
        return Some("ssh");
    }
    if is_ntp(data) {
        return Some("ntp");
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
        if let Some(host_value) = line
            .strip_prefix("Host:")
            .or_else(|| line.strip_prefix("host:"))
        {
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

fn parse_quic_sni(data: &[u8]) -> Option<String> {
    const MAX_SCAN_BYTES: usize = 1400;
    let scan = &data[..data.len().min(MAX_SCAN_BYTES)];

    if !is_quic_initial(scan) {
        return None;
    }

    if let Some(payload) = parse_quic_initial_payload(scan) {
        if let Some(host) = find_client_hello_sni(payload) {
            return Some(host);
        }
    }

    find_client_hello_sni(scan)
}

/// 检测 BitTorrent 协议
/// BT 握手: 0x13 + "BitTorrent protocol" (19 bytes)
/// DHT / uTP: 'd1:' 开头 (bencode dict)
fn is_bittorrent(data: &[u8]) -> bool {
    if data.len() >= 20 && data[0] == 19 && &data[1..20] == b"BitTorrent protocol" {
        return true;
    }
    if data.len() >= 4 && data.starts_with(b"d1:") {
        return true;
    }
    false
}

/// 检测 STUN 协议 (RFC 5389)
/// STUN 消息: 前 2 位为 00, magic cookie = 0x2112A442 at offset 4
fn is_stun(data: &[u8]) -> bool {
    if data.len() < 20 {
        return false;
    }
    // 前 2 位必须为 0
    if data[0] & 0xC0 != 0 {
        return false;
    }
    // Magic cookie at offset 4-7
    data[4] == 0x21 && data[5] == 0x12 && data[6] == 0xA4 && data[7] == 0x42
}

fn is_quic_initial(data: &[u8]) -> bool {
    if data.len() < 6 {
        return false;
    }

    let first = data[0];
    let is_long_header = first & 0x80 != 0;
    let long_packet_type = (first >> 4) & 0x03;
    if !is_long_header || long_packet_type != 0x00 {
        return false;
    }

    let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    version != 0
}

/// 检测 DTLS ClientHello
/// DTLS record: ContentType=0x16, version 0xFEFF(1.0) 或 0xFEFD(1.2)
fn is_dtls(data: &[u8]) -> bool {
    if data.len() < 13 {
        return false;
    }
    // ContentType = Handshake (0x16)
    if data[0] != 0x16 {
        return false;
    }
    // DTLS version: 0xFEFF (1.0) or 0xFEFD (1.2)
    let version = u16::from_be_bytes([data[1], data[2]]);
    matches!(version, 0xFEFF | 0xFEFD)
}

/// 检测 SSH 协议 (RFC 4253)
/// SSH 握手以 "SSH-" 开头，后跟版本号
fn is_ssh(data: &[u8]) -> bool {
    if !data.starts_with(b"SSH-") {
        return false;
    }

    let window = &data[..data.len().min(255)];
    let Some(newline_pos) = window.iter().position(|&b| b == b'\n') else {
        return false;
    };

    let mut line = &window[..newline_pos];
    if let Some(stripped) = line.strip_suffix(b"\r") {
        line = stripped;
    }

    if line.len() < 9 {
        return false;
    }

    let Some(rest) = line.strip_prefix(b"SSH-") else {
        return false;
    };
    let Some(version_sep) = rest.iter().position(|&b| b == b'-') else {
        return false;
    };

    let proto = &rest[..version_sep];
    if proto != b"2.0" && proto != b"1.99" {
        return false;
    }

    let software = &rest[version_sep + 1..];
    !software.is_empty()
        && software
            .iter()
            .all(|b| b.is_ascii() && !b.is_ascii_control())
}

/// 检测 NTP 协议 (RFC 5905)
/// NTP 包: 最小 48 字节, Version 3-4, Mode 1-5
pub fn is_ntp(data: &[u8]) -> bool {
    if data.len() < 48 {
        return false;
    }
    let first = data[0];
    let version = (first >> 3) & 0x07; // bits 3-5
    let mode = first & 0x07; // bits 0-2
                             // NTP v3 or v4, Mode: 1=symmetric active, 2=symmetric passive, 3=client, 4=server, 5=broadcast
    (version == 3 || version == 4) && (1..=5).contains(&mode)
}

/// 解析 NTP 响应时间戳（Transmit Timestamp, 偏移 40-47）
/// 返回 Unix 时间戳（秒 + 小数部分）
pub fn parse_ntp_timestamp(data: &[u8]) -> Option<(u64, f64)> {
    if data.len() < 48 || !is_ntp(data) {
        return None;
    }
    // NTP 模式检查：只解析 server(4) 或 broadcast(5) 响应
    let mode = data[0] & 0x07;
    if mode != 4 && mode != 5 {
        return None;
    }
    // Transmit Timestamp 在偏移 40-47
    let seconds = u32::from_be_bytes([data[40], data[41], data[42], data[43]]) as u64;
    let fraction = u32::from_be_bytes([data[44], data[45], data[46], data[47]]);
    if seconds == 0 {
        return None;
    }
    // NTP epoch (1900) → Unix epoch (1970) 差值: 2208988800 秒
    const NTP_UNIX_OFFSET: u64 = 2_208_988_800;
    let unix_seconds = seconds.checked_sub(NTP_UNIX_OFFSET)?;
    let frac = (fraction as f64) / (u32::MAX as f64 + 1.0);
    Some((unix_seconds, frac))
}

fn parse_quic_initial_payload(data: &[u8]) -> Option<&[u8]> {
    if !is_quic_initial(data) {
        return None;
    }

    let mut pos = 5;
    let dcid_len = *data.get(pos)? as usize;
    pos += 1;
    pos = pos.checked_add(dcid_len)?;

    let scid_len = *data.get(pos)? as usize;
    pos += 1;
    pos = pos.checked_add(scid_len)?;

    let (token_len, token_len_bytes) = parse_quic_varint(data.get(pos..)?)?;
    pos = pos.checked_add(token_len_bytes)?;
    pos = pos.checked_add(token_len)?;

    let (payload_len, payload_len_bytes) = parse_quic_varint(data.get(pos..)?)?;
    pos = pos.checked_add(payload_len_bytes)?;

    let pn_len = ((data[0] & 0x03) + 1) as usize;
    pos = pos.checked_add(pn_len)?;

    let payload_end = pos.checked_add(payload_len.saturating_sub(pn_len))?;
    data.get(pos..payload_end)
}

fn parse_quic_varint(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    let prefix = first >> 6;
    let len = 1usize << prefix;
    let slice = data.get(..len)?;

    let value = match len {
        1 => (slice[0] & 0x3f) as u64,
        2 => (((slice[0] & 0x3f) as u64) << 8) | slice[1] as u64,
        4 => {
            (((slice[0] & 0x3f) as u64) << 24)
                | ((slice[1] as u64) << 16)
                | ((slice[2] as u64) << 8)
                | (slice[3] as u64)
        }
        8 => {
            (((slice[0] & 0x3f) as u64) << 56)
                | ((slice[1] as u64) << 48)
                | ((slice[2] as u64) << 40)
                | ((slice[3] as u64) << 32)
                | ((slice[4] as u64) << 24)
                | ((slice[5] as u64) << 16)
                | ((slice[6] as u64) << 8)
                | (slice[7] as u64)
        }
        _ => return None,
    };

    usize::try_from(value).ok().map(|v| (v, len))
}

fn find_client_hello_sni(data: &[u8]) -> Option<String> {
    let scan_len = data.len().min(1200);
    for i in 0..scan_len.saturating_sub(4) {
        if data[i] != 0x01 {
            continue;
        }

        let hs_len =
            ((data[i + 1] as usize) << 16) | ((data[i + 2] as usize) << 8) | (data[i + 3] as usize);
        if hs_len < 40 {
            continue;
        }

        let body_start = i + 4;
        let body_end = body_start + hs_len;
        let body = if let Some(body) = data.get(body_start..body_end) {
            body
        } else {
            continue;
        };

        if let Some(host) = parse_client_hello_body_sni(body) {
            return Some(host);
        }
    }
    None
}

fn parse_client_hello_body_sni(body: &[u8]) -> Option<String> {
    if body.len() < 34 {
        return None;
    }

    let mut pos = 34;
    let session_id_len = *body.get(pos)? as usize;
    pos += 1 + session_id_len;

    if pos + 2 > body.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    if pos >= body.len() {
        return None;
    }
    let compression_len = body[pos] as usize;
    pos += 1 + compression_len;

    if pos + 2 > body.len() {
        return None;
    }
    let extensions_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let extensions_end = pos + extensions_len;
    if extensions_end > body.len() {
        return None;
    }

    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > extensions_end {
            return None;
        }

        if ext_type == 0x0000 {
            return parse_sni_extension(&body[pos..pos + ext_len]).and_then(validate_domain_like);
        }

        pos += ext_len;
    }

    None
}

fn validate_domain_like(host: String) -> Option<String> {
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    if !host.is_ascii() || !host.contains('.') {
        return None;
    }
    if host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        Some(host)
    } else {
        None
    }
}

/// 检查是否为 HTTP 请求
fn is_http_request(data: &[u8]) -> bool {
    let methods: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"PUT ",
        b"HEAD ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
        b"CONNECT ",
    ];
    methods.iter().any(|m| data.starts_with(m))
}

/// 嗅探结果覆盖策略
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SniffOverrideStrategy {
    /// 使用嗅探到的域名覆盖目标地址的域名和端口
    Full,
    /// 仅覆盖域名，保留原始端口
    DomainOnly,
    /// 仅覆盖端口（从协议检测推断默认端口），保留原始域名
    PortOnly,
    /// 不覆盖，仅用于路由匹配
    RouteOnly,
}

impl SniffOverrideStrategy {
    pub fn from_str(s: &str) -> Self {
        match s {
            "full" | "override" => Self::Full,
            "domain-only" | "domain" => Self::DomainOnly,
            "port-only" | "port" => Self::PortOnly,
            "route-only" | "route" | "none" => Self::RouteOnly,
            _ => Self::Full, // default
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::DomainOnly => "domain-only",
            Self::PortOnly => "port-only",
            Self::RouteOnly => "route-only",
        }
    }
}

/// Sniff result with override strategy applied
#[derive(Debug, Clone)]
pub struct SniffResult {
    pub domain: Option<String>,
    pub protocol: Option<&'static str>,
    pub inferred_port: Option<u16>,
}

impl SniffResult {
    /// Perform full sniffing: domain extraction + protocol detection
    pub fn from_data(data: &[u8]) -> Self {
        let domain = sniff(data);
        let protocol = detect_protocol(data);
        let inferred_port = protocol.and_then(|p| match p {
            "tls" => Some(443),
            "http" => Some(80),
            "dtls" => Some(443),
            "quic" => Some(443),
            "ssh" => Some(22),
            "ntp" => Some(123),
            _ => None,
        });
        Self {
            domain,
            protocol,
            inferred_port,
        }
    }

    /// Apply override strategy to produce the final target address components
    pub fn apply_override(
        &self,
        strategy: SniffOverrideStrategy,
        original_host: &str,
        original_port: u16,
    ) -> (String, u16) {
        match strategy {
            SniffOverrideStrategy::Full => {
                let host = self.domain.as_deref().unwrap_or(original_host).to_string();
                let port = self.inferred_port.unwrap_or(original_port);
                (host, port)
            }
            SniffOverrideStrategy::DomainOnly => {
                let host = self.domain.as_deref().unwrap_or(original_host).to_string();
                (host, original_port)
            }
            SniffOverrideStrategy::PortOnly => {
                let port = self.inferred_port.unwrap_or(original_port);
                (original_host.to_string(), port)
            }
            SniffOverrideStrategy::RouteOnly => (original_host.to_string(), original_port),
        }
    }
}

/// TCP Fast Open 配置
#[derive(Debug, Clone)]
pub struct TfoConfig {
    pub enabled: bool,
    pub queue_len: u32,
}

impl Default for TfoConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            queue_len: 5,
        }
    }
}

impl TfoConfig {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            queue_len: 5,
        }
    }

    /// Generate platform-specific syscall parameters for TFO
    pub fn socket_options(&self) -> Vec<(&'static str, i32)> {
        if !self.enabled {
            return Vec::new();
        }

        let mut opts = Vec::new();
        #[cfg(target_os = "linux")]
        {
            // TCP_FASTOPEN = 23
            opts.push(("TCP_FASTOPEN", self.queue_len as i32));
        }
        #[cfg(target_os = "macos")]
        {
            // TCP_FASTOPEN = 0x105
            opts.push(("TCP_FASTOPEN", 1));
        }
        #[cfg(target_os = "windows")]
        {
            // TCP_FASTOPEN = 15
            opts.push(("TCP_FASTOPEN", 1));
        }
        opts
    }
}

/// Per-direction rate limiter: separate limits for upload and download
pub struct BiDirectionalRateLimiter {
    upload: crate::common::RateLimiter,
    download: crate::common::RateLimiter,
}

impl BiDirectionalRateLimiter {
    pub fn new(upload_bps: u64, download_bps: u64) -> Self {
        Self {
            upload: crate::common::RateLimiter::new(upload_bps),
            download: crate::common::RateLimiter::new(download_bps),
        }
    }

    pub fn try_consume_upload(&self, bytes: u64) -> u64 {
        self.upload.try_consume(bytes)
    }

    pub fn try_consume_download(&self, bytes: u64) -> u64 {
        self.download.try_consume(bytes)
    }

    pub fn upload_available(&self) -> u64 {
        self.upload.available()
    }

    pub fn download_available(&self) -> u64 {
        self.download.available()
    }

    pub fn upload_max_rate(&self) -> u64 {
        self.upload.max_rate()
    }

    pub fn download_max_rate(&self) -> u64 {
        self.download.max_rate()
    }
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

    #[test]
    fn detect_bittorrent_handshake() {
        let mut data = vec![19u8];
        data.extend_from_slice(b"BitTorrent protocol");
        data.extend_from_slice(&[0u8; 48]); // reserved + info_hash + peer_id
        assert_eq!(detect_protocol(&data), Some("bittorrent"));
        assert!(is_bittorrent(&data));
    }

    #[test]
    fn detect_bittorrent_dht() {
        let data = b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe";
        assert!(is_bittorrent(data));
    }

    #[test]
    fn detect_stun_binding_request() {
        let mut data = vec![0u8; 20];
        data[0] = 0x00;
        data[1] = 0x01; // Binding Request
        data[2] = 0x00;
        data[3] = 0x00; // Length = 0
        data[4] = 0x21;
        data[5] = 0x12;
        data[6] = 0xA4;
        data[7] = 0x42; // Magic Cookie
        assert_eq!(detect_protocol(&data), Some("stun"));
        assert!(is_stun(&data));
    }

    #[test]
    fn detect_stun_no_magic_cookie() {
        let data = vec![
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(!is_stun(&data));
    }

    #[test]
    fn detect_dtls_client_hello() {
        let mut data = vec![0u8; 20];
        data[0] = 0x16; // Handshake
        data[1] = 0xFE;
        data[2] = 0xFD; // DTLS 1.2
        assert_eq!(detect_protocol(&data), Some("dtls"));
        assert!(is_dtls(&data));
    }

    #[test]
    fn detect_dtls_1_0() {
        let mut data = vec![0u8; 20];
        data[0] = 0x16;
        data[1] = 0xFE;
        data[2] = 0xFF; // DTLS 1.0
        assert!(is_dtls(&data));
    }

    #[test]
    fn detect_dtls_not_handshake() {
        let mut data = vec![0u8; 20];
        data[0] = 0x17; // Application Data, not Handshake
        data[1] = 0xFE;
        data[2] = 0xFD;
        assert!(!is_dtls(&data));
    }

    #[test]
    fn detect_http_request() {
        assert_eq!(detect_protocol(b"GET / HTTP/1.1\r\n"), Some("http"));
        assert_eq!(detect_protocol(b"POST /api HTTP/1.1\r\n"), Some("http"));
        assert!(is_http_request(b"GET /"));
        assert!(!is_http_request(b"INVALID"));
    }

    #[test]
    fn detect_tls_protocol() {
        let hello = build_test_client_hello(b"example.com");
        assert_eq!(detect_protocol(&hello), Some("tls"));
    }

    #[test]
    fn detect_unknown_protocol() {
        assert_eq!(detect_protocol(b"random junk"), None);
    }

    #[test]
    fn quic_initial_sni_best_effort() {
        let packet = build_fake_quic_initial_with_client_hello(b"quic.example.com");
        assert_eq!(
            parse_quic_sni(&packet),
            Some("quic.example.com".to_string())
        );
        assert_eq!(sniff(&packet), Some("quic.example.com".to_string()));
    }

    #[test]
    fn detect_quic_protocol() {
        let packet = build_fake_quic_initial_with_client_hello(b"quic.example.com");
        assert_eq!(detect_protocol(&packet), Some("quic"));
    }

    #[test]
    fn detect_ssh_protocol() {
        let banner = b"SSH-2.0-OpenSSH_9.6\r\n";
        assert!(is_ssh(banner));
        assert_eq!(detect_protocol(banner), Some("ssh"));
    }

    #[test]
    fn detect_ssh_protocol_compat_199() {
        let banner = b"SSH-1.99-dropbear_2024.86\n";
        assert!(is_ssh(banner));
        assert_eq!(detect_protocol(banner), Some("ssh"));
    }

    #[test]
    fn detect_ssh_protocol_invalid() {
        assert!(!is_ssh(b"SSH-2.0-OpenSSH_9.6"));
        assert!(!is_ssh(b"SSH-3.0-foo\r\n"));
        assert!(!is_ssh(b"SSH-2.0-\r\n"));
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

    fn encode_quic_varint(v: u64) -> Vec<u8> {
        if v < 64 {
            return vec![v as u8];
        }
        if v < 16384 {
            let b0 = 0x40 | ((v >> 8) as u8 & 0x3f);
            let b1 = (v & 0xff) as u8;
            return vec![b0, b1];
        }
        if v < (1 << 30) {
            let b0 = 0x80 | ((v >> 24) as u8 & 0x3f);
            let b1 = ((v >> 16) & 0xff) as u8;
            let b2 = ((v >> 8) & 0xff) as u8;
            let b3 = (v & 0xff) as u8;
            return vec![b0, b1, b2, b3];
        }
        let b0 = 0xc0 | ((v >> 56) as u8 & 0x3f);
        let b1 = ((v >> 48) & 0xff) as u8;
        let b2 = ((v >> 40) & 0xff) as u8;
        let b3 = ((v >> 32) & 0xff) as u8;
        let b4 = ((v >> 24) & 0xff) as u8;
        let b5 = ((v >> 16) & 0xff) as u8;
        let b6 = ((v >> 8) & 0xff) as u8;
        let b7 = (v & 0xff) as u8;
        vec![b0, b1, b2, b3, b4, b5, b6, b7]
    }

    fn build_fake_quic_initial_with_client_hello(sni: &[u8]) -> Vec<u8> {
        let tls_record = build_test_client_hello(sni);
        let handshake = tls_record[5..].to_vec();

        let mut packet = Vec::new();
        packet.push(0xC0);
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

        packet.push(8);
        packet.extend_from_slice(b"12345678");
        packet.push(8);
        packet.extend_from_slice(b"abcdefgh");

        packet.push(0x00);

        let payload_len = 1u64 + handshake.len() as u64;
        packet.extend_from_slice(&encode_quic_varint(payload_len));

        packet.push(0x01);
        packet.extend_from_slice(&handshake);
        packet
    }

    // --- Sniff Override Strategy tests ---

    #[test]
    fn sniff_override_strategy_from_str() {
        assert_eq!(
            SniffOverrideStrategy::from_str("full"),
            SniffOverrideStrategy::Full
        );
        assert_eq!(
            SniffOverrideStrategy::from_str("override"),
            SniffOverrideStrategy::Full
        );
        assert_eq!(
            SniffOverrideStrategy::from_str("domain-only"),
            SniffOverrideStrategy::DomainOnly
        );
        assert_eq!(
            SniffOverrideStrategy::from_str("domain"),
            SniffOverrideStrategy::DomainOnly
        );
        assert_eq!(
            SniffOverrideStrategy::from_str("port-only"),
            SniffOverrideStrategy::PortOnly
        );
        assert_eq!(
            SniffOverrideStrategy::from_str("route-only"),
            SniffOverrideStrategy::RouteOnly
        );
        assert_eq!(
            SniffOverrideStrategy::from_str("none"),
            SniffOverrideStrategy::RouteOnly
        );
        assert_eq!(
            SniffOverrideStrategy::from_str("unknown"),
            SniffOverrideStrategy::Full
        );
    }

    #[test]
    fn sniff_override_strategy_as_str() {
        assert_eq!(SniffOverrideStrategy::Full.as_str(), "full");
        assert_eq!(SniffOverrideStrategy::DomainOnly.as_str(), "domain-only");
        assert_eq!(SniffOverrideStrategy::PortOnly.as_str(), "port-only");
        assert_eq!(SniffOverrideStrategy::RouteOnly.as_str(), "route-only");
    }

    #[test]
    fn sniff_result_from_tls_data() {
        let hello = build_test_client_hello(b"example.com");
        let result = SniffResult::from_data(&hello);
        assert_eq!(result.domain.as_deref(), Some("example.com"));
        assert_eq!(result.protocol, Some("tls"));
        assert_eq!(result.inferred_port, Some(443));
    }

    #[test]
    fn sniff_result_from_http_data() {
        let data = b"GET / HTTP/1.1\r\nHost: http.example.com\r\n\r\n";
        let result = SniffResult::from_data(data);
        assert_eq!(result.domain.as_deref(), Some("http.example.com"));
        assert_eq!(result.protocol, Some("http"));
        assert_eq!(result.inferred_port, Some(80));
    }

    #[test]
    fn sniff_result_from_unknown_data() {
        let result = SniffResult::from_data(b"random binary data");
        assert!(result.domain.is_none());
        assert!(result.protocol.is_none());
        assert!(result.inferred_port.is_none());
    }

    #[test]
    fn sniff_result_apply_full_override() {
        let result = SniffResult {
            domain: Some("sniffed.com".to_string()),
            protocol: Some("tls"),
            inferred_port: Some(443),
        };
        let (host, port) = result.apply_override(SniffOverrideStrategy::Full, "1.2.3.4", 8080);
        assert_eq!(host, "sniffed.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn sniff_result_apply_domain_only() {
        let result = SniffResult {
            domain: Some("sniffed.com".to_string()),
            protocol: Some("tls"),
            inferred_port: Some(443),
        };
        let (host, port) =
            result.apply_override(SniffOverrideStrategy::DomainOnly, "1.2.3.4", 8080);
        assert_eq!(host, "sniffed.com");
        assert_eq!(port, 8080);
    }

    #[test]
    fn sniff_result_apply_port_only() {
        let result = SniffResult {
            domain: Some("sniffed.com".to_string()),
            protocol: Some("tls"),
            inferred_port: Some(443),
        };
        let (host, port) = result.apply_override(SniffOverrideStrategy::PortOnly, "1.2.3.4", 8080);
        assert_eq!(host, "1.2.3.4");
        assert_eq!(port, 443);
    }

    #[test]
    fn sniff_result_apply_route_only() {
        let result = SniffResult {
            domain: Some("sniffed.com".to_string()),
            protocol: Some("tls"),
            inferred_port: Some(443),
        };
        let (host, port) = result.apply_override(SniffOverrideStrategy::RouteOnly, "1.2.3.4", 8080);
        assert_eq!(host, "1.2.3.4");
        assert_eq!(port, 8080);
    }

    #[test]
    fn sniff_result_apply_no_domain() {
        let result = SniffResult {
            domain: None,
            protocol: None,
            inferred_port: None,
        };
        let (host, port) = result.apply_override(SniffOverrideStrategy::Full, "1.2.3.4", 8080);
        assert_eq!(host, "1.2.3.4");
        assert_eq!(port, 8080);
    }

    // --- TFO Config tests ---

    #[test]
    fn tfo_config_default() {
        let config = TfoConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.queue_len, 5);
    }

    #[test]
    fn tfo_config_disabled_no_options() {
        let config = TfoConfig::new(false);
        assert!(config.socket_options().is_empty());
    }

    #[test]
    fn tfo_config_enabled_has_options() {
        let config = TfoConfig::new(true);
        let opts = config.socket_options();
        assert!(!opts.is_empty());
    }

    // --- BiDirectional Rate Limiter tests ---

    #[test]
    fn bidirectional_rate_limiter_creation() {
        let limiter = BiDirectionalRateLimiter::new(1000, 2000);
        assert_eq!(limiter.upload_max_rate(), 1000);
        assert_eq!(limiter.download_max_rate(), 2000);
    }

    #[test]
    fn bidirectional_rate_limiter_consume_upload() {
        let limiter = BiDirectionalRateLimiter::new(1000, 2000);
        let consumed = limiter.try_consume_upload(500);
        assert_eq!(consumed, 500);
        assert!(limiter.upload_available() <= 500);
    }

    #[test]
    fn bidirectional_rate_limiter_consume_download() {
        let limiter = BiDirectionalRateLimiter::new(1000, 2000);
        let consumed = limiter.try_consume_download(500);
        assert_eq!(consumed, 500);
        assert!(limiter.download_available() <= 1500);
    }

    #[test]
    fn bidirectional_rate_limiter_independent() {
        let limiter = BiDirectionalRateLimiter::new(1000, 2000);
        limiter.try_consume_upload(500);
        let download = limiter.try_consume_download(2000);
        assert_eq!(download, 2000);
    }
}
