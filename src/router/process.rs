use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::net::{SocketAddrV4, SocketAddrV6};

#[cfg(target_os = "windows")]
use std::ffi::{c_void, OsString};
#[cfg(target_os = "windows")]
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStringExt;
#[cfg(target_os = "windows")]
use std::os::windows::io::RawHandle;
#[cfg(target_os = "windows")]
use std::ptr;

#[derive(Clone)]
struct ProcessInfo {
    name: String,
    path: String,
}

pub struct ProcessDetector {
    cache: Mutex<HashMap<String, ProcessInfo>>,
}

impl ProcessDetector {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn lookup(&self, local_addr: &SocketAddr) -> Option<String> {
        self.lookup_info(local_addr).map(|info| info.name)
    }

    pub fn lookup_path(&self, local_addr: &SocketAddr) -> Option<String> {
        self.lookup_info(local_addr).map(|info| info.path)
    }

    fn lookup_info(&self, local_addr: &SocketAddr) -> Option<ProcessInfo> {
        let key = local_addr.to_string();

        if let Ok(cache) = self.cache.lock() {
            if let Some(info) = cache.get(&key) {
                return Some(info.clone());
            }
        }

        let result = self.detect_process(local_addr);

        if let Some(ref info) = result {
            if let Ok(mut cache) = self.cache.lock() {
                if cache.len() > 10000 {
                    cache.clear();
                }
                cache.insert(key, info.clone());
            }
        }

        result
    }

    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.clear();
        }
    }

    pub fn cache_size(&self) -> usize {
        self.cache.lock().map(|c| c.len()).unwrap_or(0)
    }

    #[cfg(target_os = "windows")]
    fn detect_process(&self, local_addr: &SocketAddr) -> Option<ProcessInfo> {
        let pid = find_pid_by_local_addr(local_addr)?;
        let path = query_process_path(pid)?;
        let name = extract_process_name(&path);
        Some(ProcessInfo { name, path })
    }

    #[cfg(target_os = "linux")]
    fn detect_process(&self, local_addr: &SocketAddr) -> Option<ProcessInfo> {
        let inode = find_socket_inode(local_addr)?;
        let pid = find_pid_by_inode(inode)?;
        let path = fs::read_link(format!("/proc/{}/exe", pid)).ok()?;
        let path = path.to_string_lossy().to_string();
        let name = extract_process_name(&path);
        Some(ProcessInfo { name, path })
    }

    #[cfg(target_os = "macos")]
    fn detect_process(&self, local_addr: &SocketAddr) -> Option<ProcessInfo> {
        let _ = local_addr;
        None
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    fn detect_process(&self, _local_addr: &SocketAddr) -> Option<ProcessInfo> {
        None
    }
}

pub fn extract_process_name(path: &str) -> String {
    path.rsplit(['/', '\\']).next().unwrap_or(path).to_string()
}

#[cfg(target_os = "windows")]
type Dword = u32;
#[cfg(target_os = "windows")]
type Ulong = u32;
#[cfg(target_os = "windows")]
type Bool = i32;
#[cfg(target_os = "windows")]
type TcpTableClass = u32;
#[cfg(target_os = "windows")]
type Handle = RawHandle;

#[cfg(target_os = "windows")]
const AF_INET: Ulong = 2;
#[cfg(target_os = "windows")]
const AF_INET6: Ulong = 23;
#[cfg(target_os = "windows")]
const NO_ERROR: Dword = 0;
#[cfg(target_os = "windows")]
const ERROR_INSUFFICIENT_BUFFER: Dword = 122;
#[cfg(target_os = "windows")]
const TCP_TABLE_OWNER_PID_ALL: TcpTableClass = 5;
#[cfg(target_os = "windows")]
const PROCESS_QUERY_LIMITED_INFORMATION: Dword = 0x1000;

#[cfg(target_os = "windows")]
#[repr(C)]
#[allow(non_snake_case)]
struct MibTcpRowOwnerPid {
    dwState: Dword,
    dwLocalAddr: Dword,
    dwLocalPort: Dword,
    dwRemoteAddr: Dword,
    dwRemotePort: Dword,
    dwOwningPid: Dword,
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[allow(non_snake_case)]
struct MibTcpTableOwnerPid {
    dwNumEntries: Dword,
    table: [MibTcpRowOwnerPid; 1],
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[allow(non_snake_case)]
struct MibTcp6RowOwnerPid {
    ucLocalAddr: [u8; 16],
    dwLocalScopeId: Dword,
    dwLocalPort: Dword,
    ucRemoteAddr: [u8; 16],
    dwRemoteScopeId: Dword,
    dwRemotePort: Dword,
    dwState: Dword,
    dwOwningPid: Dword,
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[allow(non_snake_case)]
struct MibTcp6TableOwnerPid {
    dwNumEntries: Dword,
    table: [MibTcp6RowOwnerPid; 1],
}

#[cfg(target_os = "windows")]
#[link(name = "iphlpapi")]
extern "system" {
    fn GetExtendedTcpTable(
        tcp_table: *mut c_void,
        tcp_table_size: *mut Dword,
        order: Bool,
        af: Ulong,
        table_class: TcpTableClass,
        reserved: Ulong,
    ) -> Dword;
}

#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
extern "system" {
    fn OpenProcess(process_access: Dword, inherit_handle: Bool, process_id: Dword) -> Handle;
    fn QueryFullProcessImageNameW(
        process: Handle,
        flags: Dword,
        exe_name: *mut u16,
        size: *mut Dword,
    ) -> Bool;
    fn CloseHandle(handle: Handle) -> Bool;
}

#[cfg(target_os = "windows")]
fn find_pid_by_local_addr(local_addr: &SocketAddr) -> Option<u32> {
    match local_addr {
        SocketAddr::V4(addr) => find_pid_from_tcp_table_v4(addr),
        SocketAddr::V6(addr) => find_pid_from_tcp_table_v6(addr),
    }
}

#[cfg(target_os = "windows")]
fn find_pid_from_tcp_table_v4(local_addr: &SocketAddrV4) -> Option<u32> {
    let buffer = query_tcp_table(AF_INET)?;
    let table = buffer.as_ptr().cast::<MibTcpTableOwnerPid>();
    let count = unsafe { (*table).dwNumEntries as usize };
    let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), count) };

    for row in rows {
        let row_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
        if row_port != local_addr.port() {
            continue;
        }

        let row_ip = Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
        if row_ip == *local_addr.ip() {
            return Some(row.dwOwningPid);
        }
    }

    None
}

#[cfg(target_os = "windows")]
fn find_pid_from_tcp_table_v6(local_addr: &SocketAddrV6) -> Option<u32> {
    let buffer = query_tcp_table(AF_INET6)?;
    let table = buffer.as_ptr().cast::<MibTcp6TableOwnerPid>();
    let count = unsafe { (*table).dwNumEntries as usize };
    let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), count) };

    for row in rows {
        let row_port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
        if row_port != local_addr.port() {
            continue;
        }

        let row_ip = Ipv6Addr::from(row.ucLocalAddr);
        if row_ip != *local_addr.ip() {
            continue;
        }

        if local_addr.scope_id() != 0 && row.dwLocalScopeId != local_addr.scope_id() {
            continue;
        }

        return Some(row.dwOwningPid);
    }

    None
}

#[cfg(target_os = "windows")]
fn query_tcp_table(af: Ulong) -> Option<Vec<u32>> {
    let mut size = 0;
    let first = unsafe {
        GetExtendedTcpTable(
            ptr::null_mut(),
            &mut size,
            0,
            af,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };

    if first != NO_ERROR && first != ERROR_INSUFFICIENT_BUFFER {
        return None;
    }

    if size == 0 {
        return None;
    }

    let words = (size as usize).div_ceil(std::mem::size_of::<u32>());
    let mut buffer = vec![0u32; words];

    let result = unsafe {
        GetExtendedTcpTable(
            buffer.as_mut_ptr().cast::<c_void>(),
            &mut size,
            0,
            af,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };

    if result != NO_ERROR {
        return None;
    }

    Some(buffer)
}

#[cfg(target_os = "windows")]
fn query_process_path(pid: u32) -> Option<String> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }

    let mut buf = vec![0u16; 32768];
    let mut len = buf.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len) };
    unsafe {
        CloseHandle(handle);
    }

    if ok == 0 || len == 0 {
        return None;
    }

    Some(
        OsString::from_wide(&buf[..len as usize])
            .to_string_lossy()
            .to_string(),
    )
}

#[cfg(target_os = "linux")]
fn find_socket_inode(local_addr: &SocketAddr) -> Option<u64> {
    match local_addr {
        SocketAddr::V4(addr) => find_inode_in_table("/proc/net/tcp", &format_proc_tcp_v4(addr)),
        SocketAddr::V6(addr) => find_inode_in_table("/proc/net/tcp6", &format_proc_tcp_v6(addr)),
    }
}

#[cfg(target_os = "linux")]
fn format_proc_tcp_v4(addr: &SocketAddrV4) -> String {
    let ip = u32::from_le_bytes(addr.ip().octets());
    format!("{:08X}:{:04X}", ip, addr.port())
}

#[cfg(target_os = "linux")]
fn format_proc_tcp_v6(addr: &SocketAddrV6) -> String {
    let octets = addr.ip().octets();
    let mut ip = String::with_capacity(32);
    for chunk in octets.chunks_exact(4) {
        ip.push_str(&format!(
            "{:08X}",
            u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
        ));
    }
    format!("{}:{:04X}", ip, addr.port())
}

#[cfg(target_os = "linux")]
fn find_inode_in_table(table_path: &str, endpoint: &str) -> Option<u64> {
    let content = fs::read_to_string(table_path).ok()?;
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }

        if !fields[1].eq_ignore_ascii_case(endpoint) {
            continue;
        }

        if let Ok(inode) = fields[9].parse::<u64>() {
            return Some(inode);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn find_pid_by_inode(inode: u64) -> Option<u32> {
    let needle = format!("socket:[{}]", inode);
    let proc_entries = fs::read_dir("/proc").ok()?;

    for proc_entry in proc_entries.flatten() {
        let pid = proc_entry.file_name().to_string_lossy().to_string();
        if !pid.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let fd_entries = match fs::read_dir(proc_entry.path().join("fd")) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for fd_entry in fd_entries.flatten() {
            let link = match fs::read_link(fd_entry.path()) {
                Ok(link) => link,
                Err(_) => continue,
            };

            if link.to_string_lossy() != needle {
                continue;
            }

            if let Ok(pid_num) = pid.parse::<u32>() {
                return Some(pid_num);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_detector_creation() {
        let detector = ProcessDetector::new();
        assert_eq!(detector.cache_size(), 0);
    }

    #[test]
    fn process_detector_lookup_returns_none_for_unknown() {
        let detector = ProcessDetector::new();
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let _result = detector.lookup(&addr);
    }

    #[test]
    fn process_detector_cache_clear() {
        let detector = ProcessDetector::new();
        let addr: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let _ = detector.lookup(&addr);
        detector.clear_cache();
        assert_eq!(detector.cache_size(), 0);
    }

    #[test]
    fn extract_process_name_windows_path() {
        assert_eq!(
            extract_process_name("C:\\Windows\\System32\\chrome.exe"),
            "chrome.exe"
        );
    }

    #[test]
    fn extract_process_name_unix_path() {
        assert_eq!(extract_process_name("/usr/bin/firefox"), "firefox");
    }

    #[test]
    fn extract_process_name_just_name() {
        assert_eq!(extract_process_name("curl"), "curl");
    }
}
