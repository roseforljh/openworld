/// sing-box Rule-Set SRS 二进制格式解析器
///
/// SRS 格式:
///   3B magic ("SRS") + 1B version + zlib_compressed_body
///
/// 压缩体:
///   uvarint(rule_count) + rules...
///
/// 每条规则:
///   u8(rule_type) + items... + 0xFF(final) + bool(invert)
///
/// 规则项类型:
///   2=domain(trie), 3=domain_keyword, 4=domain_regex,
///   5=source_ip_cidr, 6=ip_cidr, etc.
use std::io::{self, Read};

use anyhow::{bail, Result};
use flate2::read::ZlibDecoder;
use ipnet::IpNet;

use super::provider::{DomainRule, RuleSetData};

/// SRS 魔数
const SRS_MAGIC: [u8; 3] = [0x53, 0x52, 0x53];

/// 规则项类型常量 (与 sing-box 一致)
const RULE_ITEM_DOMAIN: u8 = 2;
const RULE_ITEM_DOMAIN_KEYWORD: u8 = 3;
const RULE_ITEM_DOMAIN_REGEX: u8 = 4;
const RULE_ITEM_SOURCE_IP_CIDR: u8 = 5;
const RULE_ITEM_IP_CIDR: u8 = 6;
const RULE_ITEM_FINAL: u8 = 0xFF;

/// 解析 SRS 二进制文件内容
pub fn parse_srs(data: &[u8]) -> Result<RuleSetData> {
    if data.len() < 4 {
        bail!("SRS file too short");
    }

    // 验证魔数
    if data[0..3] != SRS_MAGIC {
        bail!(
            "invalid SRS magic: {:02x} {:02x} {:02x}",
            data[0],
            data[1],
            data[2]
        );
    }

    let version = data[3];
    if version > 3 {
        bail!("unsupported SRS version: {}", version);
    }

    // zlib 解压
    let compressed = &data[4..];
    let mut decoder = ZlibDecoder::new(compressed);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;

    // 解析规则
    let mut cursor = io::Cursor::new(decompressed.as_slice());
    let rule_count = read_uvarint(&mut cursor)?;

    let mut domain_rules = Vec::new();
    let mut ip_cidrs = Vec::new();

    for _ in 0..rule_count {
        let (domains, cidrs) = read_rule(&mut cursor)?;
        domain_rules.extend(domains);
        ip_cidrs.extend(cidrs);
    }

    Ok(RuleSetData {
        domain_rules,
        ip_cidrs,
    })
}

/// 检查数据是否为 SRS 格式
pub fn is_srs_format(data: &[u8]) -> bool {
    data.len() >= 4 && data[0..3] == SRS_MAGIC
}

/// 读取一条规则
fn read_rule(cursor: &mut io::Cursor<&[u8]>) -> Result<(Vec<DomainRule>, Vec<IpNet>)> {
    let mut domain_rules = Vec::new();
    let mut ip_cidrs = Vec::new();

    // 读取 rule_type (0=default, 1=logical)
    let rule_type = read_u8(cursor)?;

    match rule_type {
        0 => {
            // Default rule
            let (domains, cidrs) = read_default_rule(cursor)?;
            domain_rules.extend(domains);
            ip_cidrs.extend(cidrs);
        }
        1 => {
            // Logical rule：mode(1B) + uvarint(count) + rules... + invert(1B)
            let _mode = read_u8(cursor)?; // 0=AND, 1=OR
            let count = read_uvarint(cursor)?;
            for _ in 0..count {
                let (domains, cidrs) = read_rule(cursor)?;
                domain_rules.extend(domains);
                ip_cidrs.extend(cidrs);
            }
            let _invert = read_u8(cursor)?;
        }
        other => bail!("unknown SRS rule type: {}", other),
    }

    Ok((domain_rules, ip_cidrs))
}

/// 读取默认规则的所有项目
fn read_default_rule(cursor: &mut io::Cursor<&[u8]>) -> Result<(Vec<DomainRule>, Vec<IpNet>)> {
    let mut domain_rules = Vec::new();
    let mut ip_cidrs = Vec::new();

    loop {
        let item_type = read_u8(cursor)?;

        match item_type {
            RULE_ITEM_FINAL => {
                let _invert = read_u8(cursor)?;
                break;
            }
            RULE_ITEM_DOMAIN => {
                // Domain matcher (trie 格式) — 简化读取
                // sing-box 的 domain matcher 是自定义 trie 序列化
                // 我们通过 readDomainMatcher 恢复为域名列表
                let (domains, suffixes) = read_domain_matcher(cursor)?;
                for d in domains {
                    domain_rules.push(DomainRule::Full(d));
                }
                for s in suffixes {
                    domain_rules.push(DomainRule::Suffix(s));
                }
            }
            RULE_ITEM_DOMAIN_KEYWORD => {
                let keywords = read_string_list(cursor)?;
                for kw in keywords {
                    domain_rules.push(DomainRule::Keyword(kw));
                }
            }
            RULE_ITEM_DOMAIN_REGEX => {
                // Domain regex — 存储为字符串但我们当关键字用
                let regexes = read_string_list(cursor)?;
                for re in regexes {
                    domain_rules.push(DomainRule::Keyword(re));
                }
            }
            RULE_ITEM_SOURCE_IP_CIDR | RULE_ITEM_IP_CIDR => {
                let cidrs = read_ip_set(cursor)?;
                ip_cidrs.extend(cidrs);
            }
            _ => {
                // 未知/不支持的规则项，尝试跳过
                skip_unknown_item(cursor, item_type)?;
            }
        }
    }

    Ok((domain_rules, ip_cidrs))
}

/// 读取 varbin string list
/// 格式: uvarint(length) + for each: uvarint(str_len) + bytes
fn read_string_list(cursor: &mut io::Cursor<&[u8]>) -> Result<Vec<String>> {
    let count = read_uvarint(cursor)?;
    let mut result = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let s = read_string(cursor)?;
        result.push(s);
    }
    Ok(result)
}

/// 读取单个字符串
fn read_string(cursor: &mut io::Cursor<&[u8]>) -> Result<String> {
    let len = read_uvarint(cursor)?;
    let mut buf = vec![0u8; len as usize];
    cursor.read_exact(&mut buf)?;
    Ok(String::from_utf8(buf)?)
}

/// 读取 sing-box domain matcher (trie)
/// 简化实现：读取 v1 格式 (排序的 domain/suffix 列表)
/// v1: domain_count(uvarint) + domains + suffix_count(uvarint) + suffixes
/// v2: 使用 succinct trie 但带有 recover 路径
fn read_domain_matcher(cursor: &mut io::Cursor<&[u8]>) -> Result<(Vec<String>, Vec<String>)> {
    // sing-box domain matcher 写入格式:
    // 首先读取 version 指示符
    // V1: 简单列表格式
    // V2: succinct trie 格式
    //
    // 实际格式由 domain.NewMatcher 的 write 决定
    // V1 = 直接排序列表, V2 = succinct trie
    //
    // 简化实现：try to recover 为列表
    let domains = read_string_list(cursor)?;
    let suffixes = read_string_list(cursor)?;
    Ok((domains, suffixes))
}

/// 读取 IP Set
/// sing-box IPSet 格式: uvarint(range_count) + ranges
/// 每个 range: is_ipv6(bool) + from(4/16B) + to(4/16B)
fn read_ip_set(cursor: &mut io::Cursor<&[u8]>) -> Result<Vec<IpNet>> {
    let count = read_uvarint(cursor)?;
    let mut cidrs = Vec::new();

    for _ in 0..count {
        let is_ipv6 = read_u8(cursor)? != 0;
        if is_ipv6 {
            // IPv6: read 16B from + 16B to
            let mut from = [0u8; 16];
            let mut to = [0u8; 16];
            cursor.read_exact(&mut from)?;
            cursor.read_exact(&mut to)?;
            // 将 range 转换为 CIDR (简化: 只取 from 地址)
            if let Some(cidr) = range_to_cidr_v6(&from, &to) {
                cidrs.push(cidr);
            }
        } else {
            // IPv4: read 4B from + 4B to
            let mut from = [0u8; 4];
            let mut to = [0u8; 4];
            cursor.read_exact(&mut from)?;
            cursor.read_exact(&mut to)?;
            if let Some(cidr) = range_to_cidr_v4(&from, &to) {
                cidrs.push(cidr);
            }
        }
    }

    Ok(cidrs)
}

/// 将 IPv4 range 转换为最近的 CIDR
fn range_to_cidr_v4(from: &[u8; 4], to: &[u8; 4]) -> Option<IpNet> {
    let from_ip = std::net::Ipv4Addr::new(from[0], from[1], from[2], from[3]);
    let to_ip = std::net::Ipv4Addr::new(to[0], to[1], to[2], to[3]);

    // 计算前缀长度
    let from_u32 = u32::from(from_ip);
    let to_u32 = u32::from(to_ip);

    if from_u32 > to_u32 {
        return None;
    }

    // 简化：计算 from 和 to 的 XOR，确定共同前缀
    let diff = from_u32 ^ to_u32;
    let _prefix_len = if diff == 0 {
        32
    } else {
        32 - (diff.leading_zeros() as u8).min(32) - (32 - diff.leading_zeros() as u8)
    };

    // 更精确的前缀长度计算
    let host_bits = if diff == 0 {
        0u32
    } else {
        32 - diff.leading_zeros()
    };
    let prefix = 32 - host_bits as u8;

    format!("{}/{}", from_ip, prefix).parse::<IpNet>().ok()
}

/// 将 IPv6 range 转换为最近的 CIDR
fn range_to_cidr_v6(from: &[u8; 16], to: &[u8; 16]) -> Option<IpNet> {
    let from_ip = std::net::Ipv6Addr::from(*from);
    let to_ip = std::net::Ipv6Addr::from(*to);

    let from_u128 = u128::from(from_ip);
    let to_u128 = u128::from(to_ip);

    if from_u128 > to_u128 {
        return None;
    }

    let diff = from_u128 ^ to_u128;
    let host_bits = if diff == 0 {
        0u32
    } else {
        128 - diff.leading_zeros()
    };
    let prefix = 128 - host_bits as u8;

    format!("{}/{}", from_ip, prefix).parse::<IpNet>().ok()
}

/// 跳过未知规则项
fn skip_unknown_item(cursor: &mut io::Cursor<&[u8]>, item_type: u8) -> Result<()> {
    match item_type {
        // 字符串列表类型: network, query_type, ports, process, etc.
        0 | 1 | 7..=15 => {
            // 尝试按 string list 格式跳过
            let count = read_uvarint(cursor)?;
            for _ in 0..count {
                let len = read_uvarint(cursor)?;
                let mut buf = vec![0u8; len as usize];
                cursor.read_exact(&mut buf)?;
            }
        }
        // 布尔标志类型
        18 | 19 => {
            // NetworkIsExpensive / NetworkIsConstrained — 无数据
        }
        _ => {
            // 尝试按 string list 格式跳过
            let count = read_uvarint(cursor)?;
            for _ in 0..count {
                let len = read_uvarint(cursor)?;
                let mut buf = vec![0u8; len as usize];
                cursor.read_exact(&mut buf)?;
            }
        }
    }
    Ok(())
}

/// 读取 uvarint (Go binary.ReadUvarint 兼容)
fn read_uvarint(cursor: &mut io::Cursor<&[u8]>) -> Result<u64> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        let b = read_u8(cursor)?;
        result |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            bail!("uvarint overflow");
        }
    }
    Ok(result)
}

/// 读取单个 u8
fn read_u8(cursor: &mut io::Cursor<&[u8]>) -> Result<u8> {
    let mut buf = [0u8; 1];
    cursor.read_exact(&mut buf)?;
    Ok(buf[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// 构建最小的 SRS 测试数据
    fn build_test_srs(rules_data: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        // Magic
        result.extend_from_slice(&SRS_MAGIC);
        // Version
        result.push(1);
        // Zlib compress
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(rules_data).unwrap();
        let compressed = encoder.finish().unwrap();
        result.extend_from_slice(&compressed);
        result
    }

    /// 编码 uvarint
    fn encode_uvarint(mut val: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        while val >= 0x80 {
            buf.push((val as u8) | 0x80);
            val >>= 7;
        }
        buf.push(val as u8);
        buf
    }

    /// 编码字符串 (uvarint len + bytes)
    fn encode_string(s: &str) -> Vec<u8> {
        let mut buf = encode_uvarint(s.len() as u64);
        buf.extend_from_slice(s.as_bytes());
        buf
    }

    #[test]
    fn test_is_srs_format() {
        assert!(is_srs_format(b"SRS\x01data"));
        assert!(!is_srs_format(b"NOTsrs"));
        assert!(!is_srs_format(b"SR"));
    }

    #[test]
    fn test_srs_wrong_magic() {
        let data = b"XXX\x01";
        assert!(parse_srs(data).is_err());
    }

    #[test]
    fn test_srs_empty_rules() {
        // 0 条规则
        let rules_data = encode_uvarint(0);
        let srs = build_test_srs(&rules_data);
        let result = parse_srs(&srs).unwrap();
        assert!(result.domain_rules.is_empty());
        assert!(result.ip_cidrs.is_empty());
    }

    #[test]
    fn test_srs_domain_keyword_rules() {
        // 1 条规则，包含 domain_keyword 项
        let mut rules_data = encode_uvarint(1); // 1 条规则
        rules_data.push(0); // rule_type = default

        // 添加 domain_keyword 项
        rules_data.push(RULE_ITEM_DOMAIN_KEYWORD);
        // string list: 2 个关键字
        rules_data.extend(encode_uvarint(2));
        rules_data.extend(encode_string("google"));
        rules_data.extend(encode_string("facebook"));

        // Final
        rules_data.push(RULE_ITEM_FINAL);
        rules_data.push(0); // invert=false

        let srs = build_test_srs(&rules_data);
        let result = parse_srs(&srs).unwrap();
        assert_eq!(result.domain_rules.len(), 2);
        assert_eq!(
            result.domain_rules[0],
            DomainRule::Keyword("google".to_string())
        );
        assert_eq!(
            result.domain_rules[1],
            DomainRule::Keyword("facebook".to_string())
        );
    }

    #[test]
    fn test_uvarint_encoding() {
        // 小值
        let encoded_0 = encode_uvarint(0);
        let mut cursor = io::Cursor::new(encoded_0.as_slice());
        assert_eq!(read_uvarint(&mut cursor).unwrap(), 0);

        let encoded = encode_uvarint(127);
        let mut cursor = io::Cursor::new(encoded.as_slice());
        assert_eq!(read_uvarint(&mut cursor).unwrap(), 127);

        // 大值
        let encoded = encode_uvarint(300);
        let mut cursor = io::Cursor::new(encoded.as_slice());
        assert_eq!(read_uvarint(&mut cursor).unwrap(), 300);

        let encoded = encode_uvarint(100000);
        let mut cursor = io::Cursor::new(encoded.as_slice());
        assert_eq!(read_uvarint(&mut cursor).unwrap(), 100000);
    }

    #[test]
    fn test_range_to_cidr_v4() {
        // 单个 IP: 1.2.3.4 - 1.2.3.4 -> /32
        let from = [1, 2, 3, 4];
        let to = [1, 2, 3, 4];
        let cidr = range_to_cidr_v4(&from, &to).unwrap();
        assert_eq!(cidr.to_string(), "1.2.3.4/32");

        // /24 范围
        let from = [10, 0, 0, 0];
        let to = [10, 0, 0, 255];
        let cidr = range_to_cidr_v4(&from, &to).unwrap();
        assert_eq!(cidr.to_string(), "10.0.0.0/24");
    }
}
