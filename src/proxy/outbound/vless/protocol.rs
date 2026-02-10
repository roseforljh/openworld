use anyhow::Result;
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::common::{Address, ProxyStream};

/// 编码并发送 VLESS 请求头
///
/// 格式:
/// [Version: 1B = 0x00]
/// [UUID: 16B]
/// [Addons Length: 1B = 0x00]
/// [Command: 1B = 0x01 TCP]
/// [Port: 2B big-endian]
/// [AddrType: 1B] [Address: 变长]
pub async fn write_request(
    stream: &mut ProxyStream,
    uuid: &uuid::Uuid,
    target: &Address,
) -> Result<()> {
    let mut buf = BytesMut::with_capacity(64);

    // Version
    buf.put_u8(0x00);

    // UUID (16 bytes)
    buf.put_slice(uuid.as_bytes());

    // Addons length (0 = no addons)
    buf.put_u8(0x00);

    // Command: 0x01 = TCP
    buf.put_u8(0x01);

    // Port (big-endian)
    buf.put_u16(target.port());

    // Address
    target.encode_vless(&mut buf);

    stream.write_all(&buf).await?;
    stream.flush().await?;

    Ok(())
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
