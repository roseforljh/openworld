use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{BufMut, BytesMut};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::debug;

use crate::common::ProxyStream;

/// Vision padding 命令
const COMMAND_PADDING_CONTINUE: u8 = 0x00;
#[allow(dead_code)]
const COMMAND_PADDING_END: u8 = 0x01;
const COMMAND_PADDING_DIRECT: u8 = 0x02;

/// TLS 记录类型
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const TLS_CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;

/// 默认 padding 参数 [长padding阈值, 长padding随机范围, 长padding目标, 短padding随机范围]
const TESTSEED: [u32; 4] = [900, 500, 900, 256];

/// 最大 padding 块大小
const BUF_SIZE: usize = 2048;
/// padding header 大小: 5 bytes (command + content_len + padding_len)
const PADDING_HEADER_SIZE: usize = 5;
/// 首块额外的 UUID 大小
const UUID_SIZE: usize = 16;

/// 需要过滤的包数量
const PACKETS_TO_FILTER: i32 = 8;

/// Vision 流包装器
///
/// 在 TLS 流之上实现 padding/unpadding 逻辑：
/// - 写入时：对 TLS 握手阶段的数据添加 padding，检测到 Application Data 后切换到直接拷贝
/// - 读取时：移除对端发送的 padding，还原原始数据
pub struct VisionStream {
    inner: ProxyStream,
    user_uuid: [u8; 16],

    // 写入状态
    write_padding_active: bool,
    write_first_packet: bool,

    // 读取状态
    read_state: ReadState,
    read_buf: BytesMut,

    // TLS 过滤状态
    packets_filtered: i32,
    enable_xtls: bool,
    remaining_server_hello: i32,
    cipher: u16,
}

/// 读取端 unpadding 状态机
struct ReadState {
    within_padding: bool,
    remaining_command: i32,
    remaining_content: i32,
    remaining_padding: i32,
    current_command: u8,
    first_packet: bool,
    direct_copy: bool,
}

impl ReadState {
    fn new() -> Self {
        Self {
            within_padding: true,
            remaining_command: -1,
            remaining_content: -1,
            remaining_padding: -1,
            current_command: 0,
            first_packet: true,
            direct_copy: false,
        }
    }
}

impl VisionStream {
    pub fn new(inner: ProxyStream, uuid: uuid::Uuid) -> Self {
        Self {
            inner,
            user_uuid: *uuid.as_bytes(),
            write_padding_active: true,
            write_first_packet: true,
            read_state: ReadState::new(),
            read_buf: BytesMut::with_capacity(BUF_SIZE * 2),
            packets_filtered: PACKETS_TO_FILTER,
            enable_xtls: false,
            remaining_server_hello: -1,
            cipher: 0,
        }
    }

    /// 对数据添加 padding 并写入
    fn build_padded_frame(&mut self, data: &[u8]) -> BytesMut {
        let is_tls_app_data = is_tls_application_data(data);

        let command = if is_tls_app_data && self.enable_xtls {
            self.write_padding_active = false;
            COMMAND_PADDING_DIRECT
        } else {
            COMMAND_PADDING_CONTINUE
        };

        let long_padding = self.write_padding_active;
        let padding_len = calculate_padding(data.len() as i32, long_padding);

        let uuid_len = if self.write_first_packet {
            self.write_first_packet = false;
            UUID_SIZE
        } else {
            0
        };

        let total = uuid_len + PADDING_HEADER_SIZE + data.len() + padding_len;
        let mut buf = BytesMut::with_capacity(total);

        // 首块写入 UUID
        if uuid_len > 0 {
            buf.put_slice(&self.user_uuid);
        }

        // Padding header: [Command(1)] [ContentLen(2 BE)] [PaddingLen(2 BE)]
        buf.put_u8(command);
        buf.put_u16(data.len() as u16);
        buf.put_u16(padding_len as u16);

        // Content
        buf.put_slice(data);

        // Random padding
        if padding_len > 0 {
            let mut rng = rand::thread_rng();
            for _ in 0..padding_len {
                buf.put_u8(rng.gen());
            }
        }

        buf
    }

    /// TLS 过滤：分析数据包以检测 TLS 版本和密码套件
    fn filter_tls(&mut self, data: &[u8]) {
        if self.packets_filtered <= 0 || data.len() < 6 {
            return;
        }
        self.packets_filtered -= 1;

        // 检测 ServerHello: 0x16 0x03 0x03 ... 0x02
        if data[0] == TLS_CONTENT_TYPE_HANDSHAKE
            && data[1] == 0x03
            && data[2] == 0x03
            && data[5] == 0x02
        {
            self.remaining_server_hello = ((data[3] as i32) << 8 | data[4] as i32) + 5;

            // 解析密码套件
            if data.len() >= 79 && self.remaining_server_hello >= 79 {
                let session_id_len = data[43] as usize;
                let cipher_offset = 43 + session_id_len + 1;
                if cipher_offset + 2 <= data.len() {
                    self.cipher =
                        (data[cipher_offset] as u16) << 8 | data[cipher_offset + 1] as u16;
                }
            }
        }

        // 追踪 ServerHello 跨包
        if self.remaining_server_hello > 0 {
            self.remaining_server_hello -= data.len() as i32;
            if self.remaining_server_hello <= 0 {
                // 检查 TLS 1.3 supported_versions 扩展
                if contains_bytes(data, &[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]) {
                    // TLS 1.3 确认，检查密码套件是否支持
                    // 0x1305 = TLS_AES_128_CCM_8_SHA256 不支持
                    if self.cipher != 0 && self.cipher != 0x1305 {
                        self.enable_xtls = true;
                        debug!(
                            cipher = format!("0x{:04x}", self.cipher),
                            "Vision: XTLS enabled"
                        );
                    }
                }
            }
        }
    }

    /// 从 read_buf 中移除 padding，返回实际数据
    fn unpad_data(&mut self) -> BytesMut {
        let state = &mut self.read_state;
        let buf = &mut self.read_buf;

        // 初始状态检测
        if state.remaining_command == -1
            && state.remaining_content == -1
            && state.remaining_padding == -1
        {
            if state.first_packet {
                // 首块应以 UUID 开头
                if buf.len() >= UUID_SIZE + PADDING_HEADER_SIZE
                    && buf[..UUID_SIZE] == self.user_uuid
                {
                    buf.advance(UUID_SIZE);
                    state.remaining_command = PADDING_HEADER_SIZE as i32;
                    state.first_packet = false;
                } else {
                    // 非 padding 数据，直接返回
                    state.within_padding = false;
                    return buf.split();
                }
            } else {
                state.remaining_command = PADDING_HEADER_SIZE as i32;
            }
        }

        let mut output = BytesMut::new();

        while !buf.is_empty() {
            if state.remaining_command > 0 {
                // 逐字节读取 header
                let byte = buf[0];
                buf.advance(1);
                match state.remaining_command {
                    5 => state.current_command = byte,
                    4 => state.remaining_content = (byte as i32) << 8,
                    3 => state.remaining_content |= byte as i32,
                    2 => state.remaining_padding = (byte as i32) << 8,
                    1 => state.remaining_padding |= byte as i32,
                    _ => {}
                }
                state.remaining_command -= 1;
            } else if state.remaining_content > 0 {
                // 读取实际内容
                let to_read = (state.remaining_content as usize).min(buf.len());
                output.extend_from_slice(&buf[..to_read]);
                buf.advance(to_read);
                state.remaining_content -= to_read as i32;
            } else if state.remaining_padding > 0 {
                // 跳过 padding
                let to_skip = (state.remaining_padding as usize).min(buf.len());
                buf.advance(to_skip);
                state.remaining_padding -= to_skip as i32;
            }

            // 当前块处理完毕
            if state.remaining_command <= 0
                && state.remaining_content <= 0
                && state.remaining_padding <= 0
            {
                if state.current_command == COMMAND_PADDING_CONTINUE {
                    state.remaining_command = PADDING_HEADER_SIZE as i32;
                } else {
                    // End 或 Direct
                    state.remaining_command = -1;
                    state.remaining_content = -1;
                    state.remaining_padding = -1;
                    if state.current_command == COMMAND_PADDING_DIRECT {
                        state.direct_copy = true;
                        state.within_padding = false;
                    }
                    // 剩余数据直接追加
                    if !buf.is_empty() {
                        output.extend_from_slice(buf);
                        buf.clear();
                    }
                    break;
                }
            }
        }

        output
    }
}

impl AsyncRead for VisionStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 如果已切换到直接拷贝模式
        if self.read_state.direct_copy && !self.read_state.within_padding {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }

        // 如果 read_buf 中还有未处理的数据
        if !self.read_buf.is_empty() && self.read_state.within_padding {
            let unpadded = self.unpad_data();
            if !unpadded.is_empty() {
                let to_copy = unpadded.len().min(buf.remaining());
                buf.put_slice(&unpadded[..to_copy]);
                // 如果 unpadded 没有全部消费，放回 read_buf 前面
                if to_copy < unpadded.len() {
                    let remaining = unpadded[to_copy..].to_vec();
                    self.read_buf = BytesMut::from(&remaining[..]);
                }
                return Poll::Ready(Ok(()));
            }
        }

        // 从内层流读取数据
        let mut tmp_buf = [0u8; BUF_SIZE * 2];
        let mut tmp_read_buf = ReadBuf::new(&mut tmp_buf);
        match Pin::new(&mut self.inner).poll_read(cx, &mut tmp_read_buf) {
            Poll::Ready(Ok(())) => {
                let filled = tmp_read_buf.filled();
                if filled.is_empty() {
                    return Poll::Ready(Ok(()));
                }

                // TLS 过滤
                if self.packets_filtered > 0 {
                    self.filter_tls(filled);
                }

                if !self.read_state.within_padding {
                    // 不在 padding 模式，直接返回
                    let to_copy = filled.len().min(buf.remaining());
                    buf.put_slice(&filled[..to_copy]);
                    return Poll::Ready(Ok(()));
                }

                // 追加到 read_buf 并 unpad
                self.read_buf.extend_from_slice(filled);
                let unpadded = self.unpad_data();
                if !unpadded.is_empty() {
                    let to_copy = unpadded.len().min(buf.remaining());
                    buf.put_slice(&unpadded[..to_copy]);
                    if to_copy < unpadded.len() {
                        // 放回未消费的部分（prepend 到 read_buf）
                        let mut new_buf = BytesMut::from(&unpadded[to_copy..]);
                        new_buf.extend_from_slice(&self.read_buf);
                        self.read_buf = new_buf;
                    }
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for VisionStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.write_padding_active {
            // padding 阶段已结束，直接写入
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }

        // TLS 过滤
        if self.packets_filtered > 0 {
            self.filter_tls(buf);
        }

        // 限制单次写入大小
        let max_content = BUF_SIZE - PADDING_HEADER_SIZE - UUID_SIZE;
        let data_len = buf.len().min(max_content);
        let data = &buf[..data_len];

        let padded = self.build_padded_frame(data);

        // 写入 padded 数据
        match Pin::new(&mut self.inner).poll_write(cx, &padded) {
            Poll::Ready(Ok(written)) => {
                if written >= padded.len() {
                    Poll::Ready(Ok(data_len))
                } else {
                    // 部分写入 -- 简化处理，报告写入了原始数据量的比例
                    let ratio = written as f64 / padded.len() as f64;
                    let original_written = (data_len as f64 * ratio).ceil() as usize;
                    Poll::Ready(Ok(original_written.max(1).min(data_len)))
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// 检测数据是否以 TLS Application Data 记录开头
fn is_tls_application_data(data: &[u8]) -> bool {
    data.len() >= 5
        && data[0] == TLS_CONTENT_TYPE_APPLICATION_DATA
        && data[1] == 0x03
        && data[2] == 0x03
}

/// 计算 padding 长度
fn calculate_padding(content_len: i32, long_padding: bool) -> usize {
    let mut rng = rand::thread_rng();
    let padding_len = if content_len < TESTSEED[0] as i32 && long_padding {
        let random = rng.gen_range(0..TESTSEED[1] as i32);
        (random + TESTSEED[2] as i32 - content_len).max(0)
    } else {
        rng.gen_range(0..TESTSEED[3] as i32)
    };

    let max_padding = BUF_SIZE as i32 - PADDING_HEADER_SIZE as i32 - UUID_SIZE as i32 - content_len;
    padding_len.min(max_padding).max(0) as usize
}

/// 在数据中搜索子序列
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

// bytes::Buf trait 的 advance 方法
use bytes::Buf;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_tls_application_data() {
        assert!(is_tls_application_data(&[0x17, 0x03, 0x03, 0x00, 0x20]));
        assert!(!is_tls_application_data(&[0x16, 0x03, 0x03, 0x00, 0x20])); // Handshake
        assert!(!is_tls_application_data(&[0x17, 0x03])); // too short
    }

    #[test]
    fn test_contains_bytes() {
        assert!(contains_bytes(&[1, 2, 3, 4, 5], &[2, 3, 4]));
        assert!(!contains_bytes(&[1, 2, 3, 4, 5], &[2, 4]));
        assert!(contains_bytes(
            &[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04],
            &[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]
        ));
    }

    #[test]
    fn test_calculate_padding_long() {
        // 小数据 + long_padding 应产生较大 padding
        let padding = calculate_padding(100, true);
        // 目标范围约 [900-100, 900-100+500) = [800, 1300)
        assert!(padding > 0);
        assert!(padding < BUF_SIZE);
    }

    #[test]
    fn test_calculate_padding_short() {
        let padding = calculate_padding(100, false);
        assert!(padding < TESTSEED[3] as usize);
    }

    #[test]
    fn test_calculate_padding_large_content() {
        // 大数据不应使用长 padding
        let padding = calculate_padding(1500, true);
        assert!(padding < TESTSEED[3] as usize);
    }

    #[test]
    fn test_build_padded_frame_first_packet() {
        let inner: ProxyStream = Box::new(tokio::io::duplex(1).0);
        let uuid = uuid::Uuid::new_v4();
        let mut stream = VisionStream::new(inner, uuid);

        let data = b"hello";
        let frame = stream.build_padded_frame(data);

        // 首包应包含 UUID
        assert_eq!(&frame[..UUID_SIZE], uuid.as_bytes());
        // Command
        assert_eq!(frame[UUID_SIZE], COMMAND_PADDING_CONTINUE);
        // Content length
        let content_len = u16::from_be_bytes([frame[UUID_SIZE + 1], frame[UUID_SIZE + 2]]);
        assert_eq!(content_len, 5);
        // Padding length
        let padding_len = u16::from_be_bytes([frame[UUID_SIZE + 3], frame[UUID_SIZE + 4]]);
        // Content
        assert_eq!(&frame[UUID_SIZE + 5..UUID_SIZE + 5 + 5], b"hello");
        // Total size
        assert_eq!(
            frame.len(),
            UUID_SIZE + PADDING_HEADER_SIZE + 5 + padding_len as usize
        );
    }

    #[test]
    fn test_build_padded_frame_second_packet() {
        let inner: ProxyStream = Box::new(tokio::io::duplex(1).0);
        let uuid = uuid::Uuid::new_v4();
        let mut stream = VisionStream::new(inner, uuid);

        // 第一个包
        let _ = stream.build_padded_frame(b"first");
        // 第二个包不应包含 UUID
        let frame = stream.build_padded_frame(b"second");
        assert_eq!(frame[0], COMMAND_PADDING_CONTINUE);
        let content_len = u16::from_be_bytes([frame[1], frame[2]]);
        assert_eq!(content_len, 6);
    }

    #[test]
    fn test_build_padded_frame_tls_app_data() {
        let inner: ProxyStream = Box::new(tokio::io::duplex(1).0);
        let uuid = uuid::Uuid::new_v4();
        let mut stream = VisionStream::new(inner, uuid);
        stream.enable_xtls = true;
        stream.write_first_packet = false;

        // TLS Application Data 记录
        let data = [0x17, 0x03, 0x03, 0x00, 0x20, 0x00, 0x00, 0x00];
        let frame = stream.build_padded_frame(&data);

        // 应使用 COMMAND_PADDING_DIRECT
        assert_eq!(frame[0], COMMAND_PADDING_DIRECT);
        // padding 应该结束
        assert!(!stream.write_padding_active);
    }

    #[test]
    fn test_unpad_roundtrip() {
        let inner: ProxyStream = Box::new(tokio::io::duplex(1).0);
        let uuid = uuid::Uuid::new_v4();
        let mut writer = VisionStream::new(inner, uuid);

        // 构建 padded frame
        let original = b"test data for roundtrip";
        let padded = writer.build_padded_frame(original);

        // 创建 reader 并 unpad
        let inner2: ProxyStream = Box::new(tokio::io::duplex(1).0);
        let mut reader = VisionStream::new(inner2, uuid);
        reader.read_buf.extend_from_slice(&padded);

        let unpadded = reader.unpad_data();
        assert_eq!(&unpadded[..], original);
    }

    #[test]
    fn test_unpad_multiple_frames() {
        let inner: ProxyStream = Box::new(tokio::io::duplex(1).0);
        let uuid = uuid::Uuid::new_v4();
        let mut writer = VisionStream::new(inner, uuid);

        let data1 = b"first";
        let data2 = b"second";
        let frame1 = writer.build_padded_frame(data1);
        let frame2 = writer.build_padded_frame(data2);

        // 合并两个 frame
        let inner2: ProxyStream = Box::new(tokio::io::duplex(1).0);
        let mut reader = VisionStream::new(inner2, uuid);
        reader.read_buf.extend_from_slice(&frame1);
        reader.read_buf.extend_from_slice(&frame2);

        let unpadded = reader.unpad_data();
        // 应该能解出两个 frame 的数据
        assert!(unpadded.len() >= data1.len());
    }

    #[test]
    fn test_filter_tls_server_hello() {
        let inner: ProxyStream = Box::new(tokio::io::duplex(1).0);
        let uuid = uuid::Uuid::new_v4();
        let mut stream = VisionStream::new(inner, uuid);

        // 构造一个简化的 ServerHello（record length 大于实际数据，模拟跨包）
        let mut data = vec![0u8; 50];
        data[0] = 0x16; // Handshake
        data[1] = 0x03; // TLS 1.2
        data[2] = 0x03;
        data[3] = 0x01; // Length high = 256
        data[4] = 0x00; // Length low
        data[5] = 0x02; // ServerHello

        stream.filter_tls(&data);
        // record length = 256, + 5 header = 261, - 50 data = 211 remaining
        assert!(stream.remaining_server_hello > 0);
    }
}
