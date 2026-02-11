use anyhow::Result;
use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::{Address, ProxyStream};

/// VLESS 命令常量
pub const CMD_TCP: u8 = 0x01;
pub const CMD_UDP: u8 = 0x02;

/// 编码并发送 VLESS 请求头
///
/// 格式:
/// [Version: 1B = 0x00]
/// [UUID: 16B]
/// [Addons Length: 1B]
/// [Addons: 变长 (protobuf 编码的 flow)]
/// [Command: 1B]
/// [Port: 2B big-endian]
/// [AddrType: 1B] [Address: 变长]
pub async fn write_request(
    stream: &mut ProxyStream,
    uuid: &uuid::Uuid,
    target: &Address,
    flow: Option<&str>,
    command: u8,
) -> Result<()> {
    let mut buf = BytesMut::with_capacity(128);

    // Version
    buf.put_u8(0x00);

    // UUID (16 bytes)
    buf.put_slice(uuid.as_bytes());

    // Addons (protobuf 编码的 flow)
    let addons = encode_addons(flow);
    buf.put_u8(addons.len() as u8);
    if !addons.is_empty() {
        buf.put_slice(&addons);
    }

    // Command
    buf.put_u8(command);

    // Port (big-endian)
    buf.put_u16(target.port());

    // Address
    target.encode_vless(&mut buf);

    stream.write_all(&buf).await?;
    stream.flush().await?;

    Ok(())
}

/// 写入 VLESS UDP 帧: [Length: 2B Big-Endian][Payload: N bytes]
pub async fn write_udp_frame(stream: &mut ProxyStream, data: &[u8]) -> Result<()> {
    let len = data.len() as u16;
    let mut buf = BytesMut::with_capacity(2 + data.len());
    buf.put_u16(len);
    buf.put_slice(data);
    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

/// 读取 VLESS UDP 帧: [Length: 2B Big-Endian][Payload: N bytes]
pub async fn read_udp_frame(stream: &mut ProxyStream) -> Result<Bytes> {
    let len = stream.read_u16().await? as usize;
    if len == 0 {
        anyhow::bail!("VLESS UDP frame with zero length");
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(Bytes::from(buf))
}

/// 编码 Addons 为 protobuf 格式
/// Addons { Flow: string = field 1 }
/// Protobuf: tag=0x0A (field 1, wire type 2), varint length, string bytes
fn encode_addons(flow: Option<&str>) -> Vec<u8> {
    match flow {
        Some(f) if !f.is_empty() => {
            let mut buf = Vec::with_capacity(2 + f.len());
            buf.push(0x0A); // field 1, wire type 2 (length-delimited)
            buf.push(f.len() as u8); // varint length (flow 名称不超过 127 字节)
            buf.extend_from_slice(f.as_bytes());
            buf
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn write_request_ipv4() {
        let (client, mut server) = tokio::io::duplex(256);
        let mut stream: ProxyStream = Box::new(client);

        let uuid = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let target = Address::Ip("1.2.3.4:443".parse().unwrap());

        write_request(&mut stream, &uuid, &target, None, CMD_TCP)
            .await
            .unwrap();
        drop(stream);

        let mut buf = Vec::new();
        server.read_to_end(&mut buf).await.unwrap();

        assert_eq!(buf[0], 0x00); // Version
        assert_eq!(&buf[1..17], uuid.as_bytes()); // UUID
        assert_eq!(buf[17], 0x00); // Addons length = 0 (no flow)
        assert_eq!(buf[18], 0x01); // Command: TCP
        assert_eq!(u16::from_be_bytes([buf[19], buf[20]]), 443); // Port
        assert_eq!(buf[21], 0x01); // AddrType: IPv4
        assert_eq!(&buf[22..26], &[1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn write_request_udp_command() {
        let (client, mut server) = tokio::io::duplex(256);
        let mut stream: ProxyStream = Box::new(client);

        let uuid = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let target = Address::Ip("8.8.8.8:53".parse().unwrap());

        write_request(&mut stream, &uuid, &target, None, CMD_UDP)
            .await
            .unwrap();
        drop(stream);

        let mut buf = Vec::new();
        server.read_to_end(&mut buf).await.unwrap();

        assert_eq!(buf[18], 0x02); // Command: UDP
    }

    #[tokio::test]
    async fn write_request_domain() {
        let (client, mut server) = tokio::io::duplex(256);
        let mut stream: ProxyStream = Box::new(client);

        let uuid = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let target = Address::Domain("example.com".to_string(), 443);

        write_request(&mut stream, &uuid, &target, None, CMD_TCP)
            .await
            .unwrap();
        drop(stream);

        let mut buf = Vec::new();
        server.read_to_end(&mut buf).await.unwrap();

        assert_eq!(buf[17], 0x00); // Addons length = 0
        assert_eq!(buf[18], 0x01); // Command: TCP
    }

    #[tokio::test]
    async fn write_request_ipv6() {
        let (client, mut server) = tokio::io::duplex(256);
        let mut stream: ProxyStream = Box::new(client);

        let uuid = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let target = Address::Ip("[::1]:443".parse().unwrap());

        write_request(&mut stream, &uuid, &target, None, CMD_TCP)
            .await
            .unwrap();
        drop(stream);

        let mut buf = Vec::new();
        server.read_to_end(&mut buf).await.unwrap();

        assert_eq!(buf[17], 0x00); // Addons length = 0
        assert_eq!(buf[21], 0x03); // AddrType: IPv6
    }

    #[tokio::test]
    async fn write_request_with_vision_flow() {
        let (client, mut server) = tokio::io::duplex(256);
        let mut stream: ProxyStream = Box::new(client);

        let uuid = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let target = Address::Ip("1.2.3.4:443".parse().unwrap());
        let flow = "xtls-rprx-vision";

        write_request(&mut stream, &uuid, &target, Some(flow), CMD_TCP)
            .await
            .unwrap();
        drop(stream);

        let mut buf = Vec::new();
        server.read_to_end(&mut buf).await.unwrap();

        assert_eq!(buf[0], 0x00); // Version
        assert_eq!(&buf[1..17], uuid.as_bytes()); // UUID

        let addons_len = buf[17] as usize;
        assert!(addons_len > 0);
        let addons = &buf[18..18 + addons_len];
        assert_eq!(addons[0], 0x0A);
        assert_eq!(addons[1], 16);
        assert_eq!(&addons[2..], b"xtls-rprx-vision");

        let cmd_offset = 18 + addons_len;
        assert_eq!(buf[cmd_offset], 0x01); // TCP
    }

    #[test]
    fn encode_addons_none() {
        assert!(encode_addons(None).is_empty());
        assert!(encode_addons(Some("")).is_empty());
    }

    #[test]
    fn encode_addons_vision() {
        let result = encode_addons(Some("xtls-rprx-vision"));
        assert_eq!(result[0], 0x0A); // protobuf tag
        assert_eq!(result[1], 16); // string length
        assert_eq!(&result[2..], b"xtls-rprx-vision");
    }

    #[tokio::test]
    async fn read_response_ok() {
        let (mut client, server) = tokio::io::duplex(256);
        let mut stream: ProxyStream = Box::new(server);

        use tokio::io::AsyncWriteExt;
        client.write_all(&[0x00, 0x00]).await.unwrap();
        drop(client);

        read_response(&mut stream).await.unwrap();
    }

    #[tokio::test]
    async fn read_response_bad_version() {
        let (mut client, server) = tokio::io::duplex(256);
        let mut stream: ProxyStream = Box::new(server);

        use tokio::io::AsyncWriteExt;
        client.write_all(&[0x01, 0x00]).await.unwrap();
        drop(client);

        assert!(read_response(&mut stream).await.is_err());
    }

    #[tokio::test]
    async fn read_response_with_addons() {
        let (mut client, server) = tokio::io::duplex(256);
        let mut stream: ProxyStream = Box::new(server);

        use tokio::io::AsyncWriteExt;
        client
            .write_all(&[0x00, 0x03, 0xAA, 0xBB, 0xCC])
            .await
            .unwrap();
        drop(client);

        read_response(&mut stream).await.unwrap();
    }

    #[tokio::test]
    async fn udp_frame_roundtrip() {
        let (client, server) = tokio::io::duplex(1024);
        let mut write_stream: ProxyStream = Box::new(client);
        let mut read_stream: ProxyStream = Box::new(server);

        let payload = b"hello UDP world";
        write_udp_frame(&mut write_stream, payload).await.unwrap();
        drop(write_stream);

        let result = read_udp_frame(&mut read_stream).await.unwrap();
        assert_eq!(&result[..], payload);
    }

    #[tokio::test]
    async fn udp_frame_multiple() {
        let (client, server) = tokio::io::duplex(4096);
        let mut write_stream: ProxyStream = Box::new(client);
        let mut read_stream: ProxyStream = Box::new(server);

        let payloads = [b"first".as_slice(), b"second", b"third"];
        for p in &payloads {
            write_udp_frame(&mut write_stream, p).await.unwrap();
        }
        drop(write_stream);

        for p in &payloads {
            let result = read_udp_frame(&mut read_stream).await.unwrap();
            assert_eq!(&result[..], *p);
        }
    }
}

/// 读取 VLESS 响应头
///
/// 格式:
/// [Version: 1B = 0x00]
/// [Addons Length: 1B]
/// [Addons: 变长]
pub async fn read_response(stream: &mut ProxyStream) -> Result<()> {
    // Version
    let version = stream.read_u8().await?;
    if version != 0x00 {
        anyhow::bail!("unexpected VLESS response version: 0x{:02x}", version);
    }

    // Addons length
    let addons_len = stream.read_u8().await?;

    // Skip addons
    if addons_len > 0 {
        let mut addons = vec![0u8; addons_len as usize];
        stream.read_exact(&mut addons).await?;
    }

    Ok(())
}
