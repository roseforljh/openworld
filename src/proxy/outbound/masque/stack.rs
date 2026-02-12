// MASQUE 出站 — 用户态网络栈
//
// 使用 smoltcp 提供用户态 TCP/IP 栈，将 TCP/UDP 连接请求
// 转换为 IP 包，通过 CONNECT-IP 隧道传输。
//
// 这等效于 mihomo 中 sing-wireguard 的 StackDevice。

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;

/// 虚拟网络设备 — 充当 TUN 角色
///
/// 发送的 IP 包会被收集到 tx_queue 中（由 CONNECT-IP 层取走发送到隧道），
/// 从隧道收到的 IP 包放入 rx_queue 中（供 smoltcp 协议栈处理）。
struct VirtualDevice {
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl VirtualDevice {
    fn new(mtu: usize) -> Self {
        VirtualDevice {
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            mtu,
        }
    }

    /// 注入来自隧道的 IP 包
    fn inject_packet(&mut self, packet: Vec<u8>) {
        self.rx_queue.push_back(packet);
    }

    /// 取出待发送到隧道的 IP 包
    fn take_packet(&mut self) -> Option<Vec<u8>> {
        self.tx_queue.pop_front()
    }
}

struct VirtualRxToken {
    data: Vec<u8>,
}

impl RxToken for VirtualRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.data)
    }
}

struct VirtualTxToken<'a> {
    tx_queue: &'a mut VecDeque<Vec<u8>>,
}

impl<'a> TxToken for VirtualTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        self.tx_queue.push_back(buf);
        result
    }
}

impl Device for VirtualDevice {
    type RxToken<'a> = VirtualRxToken;
    type TxToken<'a> = VirtualTxToken<'a>;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(data) = self.rx_queue.pop_front() {
            Some((
                VirtualRxToken { data },
                VirtualTxToken { tx_queue: &mut self.tx_queue },
            ))
        } else {
            None
        }
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(VirtualTxToken { tx_queue: &mut self.tx_queue })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

/// 用户态网络栈状态
///
/// 包装 smoltcp 的 Interface + SocketSet，
/// 通过 VirtualDevice 与 CONNECT-IP 隧道交互。
pub struct StackState {
    device: VirtualDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
}

impl StackState {
    /// 创建新的用户态网络栈
    ///
    /// `local_addr` — 虚拟网卡的本地 IP 地址（如 "172.16.0.2"）
    /// `mtu` — 最大传输单元
    pub fn new(local_addr: IpAddr, mtu: u16) -> Self {
        let mtu = mtu as usize;
        let mut device = VirtualDevice::new(mtu);

        let config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, SmolInstant::now());

        // 设定本地 IP 地址
        let cidr = match local_addr {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                IpCidr::new(IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(o[0], o[1], o[2], o[3])), 32)
            }
            IpAddr::V6(v6) => {
                IpCidr::new(IpAddress::Ipv6(smoltcp::wire::Ipv6Address::from(v6.octets())), 128)
            }
        };
        iface.update_ip_addrs(|addrs| {
            addrs.push(cidr).ok();
        });

        // 设置默认网关（虚拟的，所有流量都走隧道）
        iface.routes_mut().add_default_ipv4_route(
            smoltcp::wire::Ipv4Address::new(0, 0, 0, 1)
        ).ok();
        iface.routes_mut().add_default_ipv6_route(
            smoltcp::wire::Ipv6Address::from([0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        ).ok();

        let sockets = SocketSet::new(vec![]);

        debug!(local_addr = %local_addr, mtu = mtu, "MASQUE 用户态网络栈已创建");

        StackState {
            device,
            iface,
            sockets,
        }
    }

    /// 注入从隧道接收的 IP 包
    pub fn inject_packet(&mut self, packet: Vec<u8>) {
        self.device.inject_packet(packet);
    }

    /// 取出待发送到隧道的 IP 包
    pub fn take_outbound_packet(&mut self) -> Option<Vec<u8>> {
        self.device.take_packet()
    }

    /// 轮询网络栈（处理 TCP 重传、超时等）
    pub fn poll(&mut self) {
        let timestamp = SmolInstant::now();
        self.iface.poll(timestamp, &mut self.device, &mut self.sockets);
    }

    /// 创建 TCP 连接（返回 socket handle）
    pub fn create_tcp_socket(&mut self) -> SocketHandle {
        let rx_buf = tcp::SocketBuffer::new(vec![0u8; 65536]);
        let tx_buf = tcp::SocketBuffer::new(vec![0u8; 65536]);
        let socket = tcp::Socket::new(rx_buf, tx_buf);
        self.sockets.add(socket)
    }

    /// 向 TCP socket 发起连接
    pub fn tcp_connect(
        &mut self,
        handle: SocketHandle,
        remote: SocketAddr,
        local_port: u16,
    ) -> Result<()> {
        let remote_endpoint = IpEndpoint::new(
            match remote.ip() {
                IpAddr::V4(v4) => {
                    let o = v4.octets();
                    IpAddress::Ipv4(smoltcp::wire::Ipv4Address::new(o[0], o[1], o[2], o[3]))
                }
                IpAddr::V6(v6) => {
                    IpAddress::Ipv6(smoltcp::wire::Ipv6Address::from(v6.octets()))
                }
            },
            remote.port(),
        );
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        socket.connect(
            self.iface.context(),
            remote_endpoint,
            local_port,
        ).map_err(|e| anyhow::anyhow!("TCP connect failed: {}", e))?;
        Ok(())
    }

    /// 检查 TCP 连接状态
    pub fn tcp_is_active(&self, handle: SocketHandle) -> bool {
        let socket = self.sockets.get::<tcp::Socket>(handle);
        socket.is_active()
    }

    /// 检查 TCP 连接是否已建立
    pub fn tcp_may_send(&self, handle: SocketHandle) -> bool {
        let socket = self.sockets.get::<tcp::Socket>(handle);
        socket.may_send()
    }

    /// TCP 发送数据
    pub fn tcp_send(&mut self, handle: SocketHandle, data: &[u8]) -> Result<usize> {
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        let n = socket.send_slice(data)
            .map_err(|e| anyhow::anyhow!("TCP send failed: {}", e))?;
        Ok(n)
    }

    /// TCP 接收数据
    pub fn tcp_recv(&mut self, handle: SocketHandle, buf: &mut [u8]) -> Result<usize> {
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        let n = socket.recv_slice(buf)
            .map_err(|e| anyhow::anyhow!("TCP recv failed: {}", e))?;
        Ok(n)
    }
}

/// 线程安全的网络栈包装
pub type SharedStack = Arc<Mutex<StackState>>;

/// 创建共享网络栈
pub fn create_stack(local_addr: IpAddr, mtu: u16) -> SharedStack {
    Arc::new(Mutex::new(StackState::new(local_addr, mtu)))
}

/// 基于 smoltcp 的 TCP 流
///
/// 实现 AsyncRead + AsyncWrite，可被包装为 ProxyStream。
pub struct StackTcpStream {
    pub(crate) stack: SharedStack,
    pub(crate) handle: SocketHandle,
    #[allow(dead_code)]
    local_port: u16,
}

impl StackTcpStream {
    pub fn new(stack: SharedStack, remote: SocketAddr) -> Result<Self> {
        // 分配本地端口
        let local_port = allocate_port();

        let handle = {
            let mut s = stack.lock().unwrap();
            let handle = s.create_tcp_socket();
            s.tcp_connect(handle, remote, local_port)?;
            handle
        };

        Ok(Self {
            stack,
            handle,
            local_port,
        })
    }
}

impl AsyncRead for StackTcpStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let mut stack = this.stack.lock().unwrap();
        stack.poll();

        let unfilled = buf.initialize_unfilled();
        match stack.tcp_recv(this.handle, unfilled) {
            Ok(0) => {
                // 没有数据，注册 waker 等待后续轮询
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
            Ok(n) => {
                buf.advance(n);
                std::task::Poll::Ready(Ok(()))
            }
            Err(e) => {
                if stack.tcp_is_active(this.handle) {
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                } else {
                    std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        e.to_string(),
                    )))
                }
            }
        }
    }
}

impl AsyncWrite for StackTcpStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let mut stack = this.stack.lock().unwrap();
        stack.poll();

        match stack.tcp_send(this.handle, buf) {
            Ok(0) => {
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
            Ok(n) => std::task::Poll::Ready(Ok(n)),
            Err(e) => {
                if stack.tcp_may_send(this.handle) {
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                } else {
                    std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        e.to_string(),
                    )))
                }
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let mut stack = this.stack.lock().unwrap();
        stack.poll();
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let mut stack = this.stack.lock().unwrap();
        // TCP close
        let socket = stack.sockets.get_mut::<tcp::Socket>(this.handle);
        socket.close();
        stack.poll();
        std::task::Poll::Ready(Ok(()))
    }
}

impl Unpin for StackTcpStream {}

/// 简单端口分配器
fn allocate_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT_PORT: AtomicU16 = AtomicU16::new(49152);
    let port = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
    if port == 0 {
        NEXT_PORT.store(49153, Ordering::Relaxed);
        49152
    } else {
        port
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_creation() {
        let stack = StackState::new(IpAddr::V4(std::net::Ipv4Addr::new(172, 16, 0, 2)), 1280);
        assert_eq!(stack.device.mtu, 1280);
    }

    #[test]
    fn test_virtual_device() {
        let mut dev = VirtualDevice::new(1500);
        assert!(dev.take_packet().is_none());
        dev.inject_packet(vec![1, 2, 3]);
        assert_eq!(dev.rx_queue.len(), 1);
    }

    #[test]
    fn test_port_allocation() {
        let p1 = allocate_port();
        let p2 = allocate_port();
        assert_ne!(p1, p2);
        assert!(p1 >= 49152);
    }
}
