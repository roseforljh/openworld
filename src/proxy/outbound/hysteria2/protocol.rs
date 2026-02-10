use anyhow::Result;
use rand::Rng;

/// QUIC Varint 编码
/// - 1B: 值 0~63 (前缀 00)
/// - 2B: 值 0~16383 (前缀 01)
/// - 4B: 值 0~1073741823 (前缀 10)
/// - 8B: 值 0~4611686018427387903 (前缀 11)
pub fn encode_varint(value: u64) -> Vec<u8> {
    if value <= 63 {
        vec![value as u8]
    } else if value <= 16383 {
        let v = (value as u16) | 0x4000;
        v.to_be_bytes().to_vec()
    } else if value <= 1073741823 {
        let v = (value as u32) | 0x80000000;
        v.to_be_bytes().to_vec()
    } else {
        let v = value | 0xC000000000000000;
        v.to_be_bytes().to_vec()
    }
}

/// QUIC Varint 解码（从字节切片读取）
pub fn decode_varint_from_buf(buf: &[u8]) -> Result<(u64, usize)> {
    if buf.is_empty() {
        anyhow::bail!("empty buffer for varint decode");
    }
    let first = buf[0];
    let prefix = first >> 6;
    let mut value = (first & 0x3F) as u64;

    match prefix {
        0 => Ok((value, 1)),
        1 => {
            if buf.len() < 2 {
                anyhow::bail!("insufficient bytes for 2-byte varint");
            }
            value = (value << 8) | buf[1] as u64;
            Ok((value, 2))
        }
        2 => {
            if buf.len() < 4 {
                anyhow::bail!("insufficient bytes for 4-byte varint");
            }
            value = (value << 8) | buf[1] as u64;
            value = (value << 8) | buf[2] as u64;
            value = (value << 8) | buf[3] as u64;
            Ok((value, 4))
        }
        3 => {
            if buf.len() < 8 {
                anyhow::bail!("insufficient bytes for 8-byte varint");
            }
            for &b in &buf[1..8] {
                value = (value << 8) | b as u64;
            }
            Ok((value, 8))
        }
        _ => unreachable!(),
    }
}

/// 发送 Hysteria2 TCP 请求
///
/// 格式:
/// [varint: 0x401]
/// [varint: addr_len]
/// [bytes: addr_string "host:port"]
/// [varint: padding_len]
/// [bytes: random_padding]
pub async fn write_tcp_request(
    send: &mut quinn::SendStream,
    addr: &str,
) -> Result<()> {
    // 在 await 之前构建完整的缓冲区（避免 rng 跨 await 的 Send 问题）
    let buf = {
        let mut buf = Vec::new();

        // Request ID: 0x401
        buf.extend_from_slice(&encode_varint(0x401));

        // Address
        let addr_bytes = addr.as_bytes();
        buf.extend_from_slice(&encode_varint(addr_bytes.len() as u64));
        buf.extend_from_slice(addr_bytes);

        // Random padding (0~64 bytes)
        let mut rng = rand::thread_rng();
        let padding_len: usize = rng.gen_range(0..64);
        buf.extend_from_slice(&encode_varint(padding_len as u64));
        let padding: Vec<u8> = (0..padding_len).map(|_| rng.gen()).collect();
        buf.extend_from_slice(&padding);

        buf
    };

    send.write_all(&buf).await?;

    Ok(())
}

/// 读取 Hysteria2 TCP 响应
///
/// 格式:
/// [uint8: status]  (0x00=OK, 0x01=Error)
/// [varint: msg_len]
/// [bytes: msg_string]
/// [varint: padding_len]
/// [bytes: padding]
pub async fn read_tcp_response(
    recv: &mut quinn::RecvStream,
) -> Result<()> {
    // 读取足够的数据来解析响应
    // 先读取 status (1 byte) + 最多 8 bytes varint
    let mut header_buf = vec![0u8; 9];
    // 读取 status byte
    let _chunk = recv.read(&mut header_buf[..1]).await?
        .ok_or_else(|| anyhow::anyhow!("stream closed before hysteria2 response"))?;

    let status = header_buf[0];

    // 读取 msg_len varint - 先读 1 byte 判断长度
    recv.read(&mut header_buf[0..1]).await?
        .ok_or_else(|| anyhow::anyhow!("stream closed reading msg_len"))?;
    let first_byte = header_buf[0];
    let varint_len = match first_byte >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };

    let msg_len = if varint_len == 1 {
        (first_byte & 0x3F) as u64
    } else {
        let mut varint_buf = vec![first_byte];
        let mut remaining = vec![0u8; varint_len - 1];
        read_exact_quinn(recv, &mut remaining).await?;
        varint_buf.extend_from_slice(&remaining);
        let (val, _) = decode_varint_from_buf(&varint_buf)?;
        val
    };

    // 读取 message
    let mut msg_buf = vec![0u8; msg_len as usize];
    if msg_len > 0 {
        read_exact_quinn(recv, &mut msg_buf).await?;
    }

    // 读取 padding_len varint
    let mut first = [0u8; 1];
    read_exact_quinn(recv, &mut first).await?;
    let pad_varint_len = match first[0] >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };

    let padding_len = if pad_varint_len == 1 {
        (first[0] & 0x3F) as u64
    } else {
        let mut varint_buf = vec![first[0]];
        let mut remaining = vec![0u8; pad_varint_len - 1];
        read_exact_quinn(recv, &mut remaining).await?;
        varint_buf.extend_from_slice(&remaining);
        let (val, _) = decode_varint_from_buf(&varint_buf)?;
        val
    };

    // 跳过 padding
    if padding_len > 0 {
        let mut padding = vec![0u8; padding_len as usize];
        read_exact_quinn(recv, &mut padding).await?;
    }

    if status != 0x00 {
        let msg = String::from_utf8_lossy(&msg_buf);
        anyhow::bail!("hysteria2 TCP request failed: status=0x{:02x}, msg={}", status, msg);
    }

    Ok(())
}

/// 从 quinn::RecvStream 精确读取指定字节数
async fn read_exact_quinn(recv: &mut quinn::RecvStream, buf: &mut [u8]) -> Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        let n = recv.read(&mut buf[offset..]).await?
            .ok_or_else(|| anyhow::anyhow!("stream closed unexpectedly"))?;
        offset += n;
    }
    Ok(())
}
