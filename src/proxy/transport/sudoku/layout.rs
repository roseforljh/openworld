/// 字节布局模式
///
/// 定义如何将 (val, pos) 提示编码为单个字节，以及如何区分提示字节和 padding 字节。
/// 支持三种模式：ASCII（全可打印字符）、Entropy（低熵）、Custom（自定义 XVP 模式）。

/// 字节布局
pub struct ByteLayout {
    pub name: &'static str,
    /// 提示字节判断：(b & hint_mask) == hint_value 则为提示
    pub hint_mask: u8,
    pub hint_value: u8,
    /// padding 池
    pub padding_pool: Vec<u8>,
    /// 编码函数指针
    encode_hint_fn: fn(u8, u8) -> u8,
    /// 是否为 ASCII 模式（需要特殊处理 0x7F → '\n'）
    pub is_ascii: bool,
}

impl ByteLayout {
    /// 判断字节是否为提示字节
    pub fn is_hint(&self, b: u8) -> bool {
        if (b & self.hint_mask) == self.hint_value {
            return true;
        }
        // ASCII 模式下 0x7F(DEL) 映射为 '\n'
        self.is_ascii && b == b'\n'
    }

    /// 将 (val: 0..3, pos: 0..15) 编码为一个字节
    pub fn encode_hint(&self, val: u8, pos: u8) -> u8 {
        (self.encode_hint_fn)(val, pos)
    }
}

/// ASCII 布局：所有输出为可打印 ASCII 字符
pub fn new_ascii_layout() -> ByteLayout {
    let mut padding = Vec::with_capacity(32);
    for i in 0..32u8 {
        padding.push(0x20 + i);
    }
    ByteLayout {
        name: "ascii",
        hint_mask: 0x40,
        hint_value: 0x40,
        padding_pool: padding,
        encode_hint_fn: ascii_encode_hint,
        is_ascii: true,
    }
}

fn ascii_encode_hint(val: u8, pos: u8) -> u8 {
    let b = 0x40 | ((val & 0x03) << 4) | (pos & 0x0F);
    // 避免 DEL (0x7F)，映射为 '\n'
    if b == 0x7F {
        b'\n'
    } else {
        b
    }
}

/// 低熵布局：输出字节的 Hamming weight ≤ 3
pub fn new_entropy_layout() -> ByteLayout {
    let mut padding = Vec::with_capacity(16);
    for i in 0..8u8 {
        padding.push(0x80 + i);
        padding.push(0x10 + i);
    }
    ByteLayout {
        name: "entropy",
        hint_mask: 0x90,
        hint_value: 0x00,
        padding_pool: padding,
        encode_hint_fn: entropy_encode_hint,
        is_ascii: false,
    }
}

fn entropy_encode_hint(val: u8, pos: u8) -> u8 {
    ((val & 0x03) << 5) | (pos & 0x0F)
}

/// 自定义 XVP 布局
///
/// pattern 必须为 8 字符，包含恰好 2 个 'x'、2 个 'p'、4 个 'v'（不区分大小写）。
/// - x 位：标记位（hint 字节中 x 位全为 1）
/// - p 位：存储 val（0..3 的 2 bit）
/// - v 位：存储 pos（0..15 的 4 bit）
pub fn new_custom_layout(pattern: &str) -> Result<ByteLayout, String> {
    let cleaned: String = pattern.trim().to_lowercase().replace(' ', "");
    if cleaned.len() != 8 {
        return Err(format!(
            "自定义 table 必须为 8 字符，实际 {}",
            cleaned.len()
        ));
    }

    let mut x_bits: Vec<u8> = Vec::new();
    let mut p_bits: Vec<u8> = Vec::new();
    let mut v_bits: Vec<u8> = Vec::new();

    for (i, c) in cleaned.chars().enumerate() {
        let bit = 7 - i as u8;
        match c {
            'x' => x_bits.push(bit),
            'p' => p_bits.push(bit),
            'v' => v_bits.push(bit),
            _ => return Err(format!("无效字符 '{}' in custom table", c)),
        }
    }

    if x_bits.len() != 2 || p_bits.len() != 2 || v_bits.len() != 4 {
        return Err("custom table 必须包含恰好 2 个 x、2 个 p、4 个 v".to_string());
    }

    // 计算 x_mask
    let x_mask: u8 = x_bits.iter().fold(0u8, |acc, &b| acc | (1 << b));

    // padding pool: x 位去掉一个后、高 Hamming weight 的字节
    let mut padding_set = std::collections::HashSet::new();
    let mut padding = Vec::new();
    for drop in 0..x_bits.len() {
        for val in 0..4u8 {
            for pos in 0..16u8 {
                let b = custom_encode_bits(&x_bits, &p_bits, &v_bits, x_mask, val, pos, Some(drop));
                if b.count_ones() >= 5 {
                    if padding_set.insert(b) {
                        padding.push(b);
                    }
                }
            }
        }
    }

    let _x0 = x_bits[0];
    let _x1 = x_bits[1];
    let p0 = p_bits[0];
    let p1 = p_bits[1];
    let v0 = v_bits[0];
    let v1 = v_bits[1];
    let v2 = v_bits[2];
    let v3 = v_bits[3];

    // 预计算编码表（64 种 val/pos 组合）
    CUSTOM_ENCODE_TABLE.lock().unwrap().clear();
    for val in 0..4u8 {
        for pos in 0..16u8 {
            let mut out = x_mask; // 所有 x 位置 1
            if (val & 0x02) != 0 {
                out |= 1 << p0;
            }
            if (val & 0x01) != 0 {
                out |= 1 << p1;
            }
            if (pos >> 3) & 1 == 1 {
                out |= 1 << v0;
            }
            if (pos >> 2) & 1 == 1 {
                out |= 1 << v1;
            }
            if (pos >> 1) & 1 == 1 {
                out |= 1 << v2;
            }
            if pos & 1 == 1 {
                out |= 1 << v3;
            }
            let key = ((val as u16) << 4) | (pos as u16);
            CUSTOM_ENCODE_TABLE.lock().unwrap().insert(key, out);
        }
    }

    // 设置全局解码参数
    {
        let mut params = CUSTOM_DECODE_PARAMS.lock().unwrap();
        *params = Some(CustomDecodeParams {
            x_mask,
            p_bits: [p0, p1],
            v_bits: [v0, v1, v2, v3],
        });
    }

    Ok(ByteLayout {
        name: "custom",
        hint_mask: x_mask,
        hint_value: x_mask,
        padding_pool: padding,
        encode_hint_fn: custom_encode_hint_static,
        is_ascii: false,
    })
}

fn custom_encode_bits(
    x_bits: &[u8],
    p_bits: &[u8],
    v_bits: &[u8],
    x_mask: u8,
    val: u8,
    pos: u8,
    drop_x: Option<usize>,
) -> u8 {
    let mut out = x_mask;
    if let Some(drop) = drop_x {
        out &= !(1 << x_bits[drop]);
    }
    if (val & 0x02) != 0 {
        out |= 1 << p_bits[0];
    }
    if (val & 0x01) != 0 {
        out |= 1 << p_bits[1];
    }
    if (pos >> 3) & 1 == 1 {
        out |= 1 << v_bits[0];
    }
    if (pos >> 2) & 1 == 1 {
        out |= 1 << v_bits[1];
    }
    if (pos >> 1) & 1 == 1 {
        out |= 1 << v_bits[2];
    }
    if pos & 1 == 1 {
        out |= 1 << v_bits[3];
    }
    out
}

use std::collections::HashMap;
use std::sync::Mutex;

static CUSTOM_ENCODE_TABLE: std::sync::LazyLock<Mutex<HashMap<u16, u8>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

#[allow(dead_code)]
struct CustomDecodeParams {
    x_mask: u8,
    p_bits: [u8; 2],
    v_bits: [u8; 4],
}

static CUSTOM_DECODE_PARAMS: std::sync::LazyLock<Mutex<Option<CustomDecodeParams>>> =
    std::sync::LazyLock::new(|| Mutex::new(None));

fn custom_encode_hint_static(val: u8, pos: u8) -> u8 {
    let key = ((val as u16) << 4) | (pos as u16);
    *CUSTOM_ENCODE_TABLE.lock().unwrap().get(&key).unwrap_or(&0)
}

/// 解析布局模式
pub fn resolve_layout(mode: &str, custom_pattern: &str) -> Result<ByteLayout, String> {
    match mode.to_lowercase().as_str() {
        "ascii" | "prefer_ascii" => Ok(new_ascii_layout()),
        "entropy" | "prefer_entropy" | "" => {
            if !custom_pattern.trim().is_empty() {
                new_custom_layout(custom_pattern)
            } else {
                Ok(new_entropy_layout())
            }
        }
        _ => Err(format!("无效的 table-type: {}", mode)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_layout_all_hints_printable() {
        let layout = new_ascii_layout();
        for val in 0..4u8 {
            for pos in 0..16u8 {
                let b = layout.encode_hint(val, pos);
                assert!(
                    layout.is_hint(b),
                    "({}, {}) → 0x{:02X} 应该被识别为提示",
                    val,
                    pos,
                    b
                );
                // 应该是可打印字符或 \n
                assert!(
                    (b >= 0x20 && b <= 0x7E) || b == b'\n',
                    "({}, {}) → 0x{:02X} 不是可打印字符",
                    val,
                    pos,
                    b
                );
            }
        }
    }

    #[test]
    fn entropy_layout_bit_pattern() {
        let layout = new_entropy_layout();
        for val in 0..4u8 {
            for pos in 0..16u8 {
                let b = layout.encode_hint(val, pos);
                assert!(
                    layout.is_hint(b),
                    "({}, {}) → 0x{:02X} 应该被识别为提示",
                    val,
                    pos,
                    b
                );
                // entropy 布局的约束：bit 7 和 bit 4 都为 0
                assert_eq!(
                    b & 0x90,
                    0x00,
                    "({}, {}) → 0x{:02X} 不满足 entropy 位模式 (b & 0x90) == 0",
                    val,
                    pos,
                    b
                );
            }
        }
    }

    #[test]
    fn padding_not_detected_as_hint() {
        for layout in [new_ascii_layout(), new_entropy_layout()] {
            for &pad in &layout.padding_pool {
                assert!(
                    !layout.is_hint(pad),
                    "{}: padding 0x{:02X} 被错误识别为提示",
                    layout.name,
                    pad
                );
            }
        }
    }
}
