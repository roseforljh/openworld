/// Sudoku 编解码表
///
/// 核心数据结构：将每个字节 (0..255) 映射为一组 4 字节提示，
/// 这些提示唯一确定一个 4x4 数独网格。
use std::collections::HashMap;

use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};

use super::grid::{generate_all_grids, Grid};
use super::layout::{resolve_layout, ByteLayout};

/// Sudoku 编解码表
pub struct Table {
    /// 编码表：encode_table[byte_value] = Vec<[hint0, hint1, hint2, hint3]>
    /// 每个字节可能有多种编码方式（不同位置组合），随机选一种
    pub encode_table: Vec<Vec<[u8; 4]>>,
    /// 解码表：排序后的 4 提示 → 原始字节值
    pub decode_map: HashMap<u32, u8>,
    /// padding 池
    pub padding_pool: Vec<u8>,
    /// 布局
    pub layout: ByteLayout,
}

impl Table {
    /// 构建编解码表
    ///
    /// - `key`: 预共享密钥（用于确定性洗牌网格）
    /// - `mode`: "prefer_ascii" | "prefer_entropy" | ""
    /// - `custom_pattern`: 自定义 XVP 模式（可空）
    pub fn new(key: &str, mode: &str, custom_pattern: &str) -> Result<Self, String> {
        let layout = resolve_layout(mode, custom_pattern)?;

        // 生成全部 288 个有效数独网格
        let all_grids = generate_all_grids();

        // 用 key 的 SHA256 前 8 字节作为种子确定性洗牌
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let hash = hasher.finalize();
        let seed = u64::from_be_bytes(hash[..8].try_into().unwrap());
        let mut rng = ChaCha8Rng::seed_from_u64(seed);

        let mut shuffled_grids: Vec<Grid> = all_grids.clone();
        shuffled_grids.shuffle(&mut rng);

        // 预计算 C(16,4) = 1820 种位置组合
        let combinations = generate_combinations(16, 4);

        // 构建映射表
        let mut encode_table: Vec<Vec<[u8; 4]>> = vec![Vec::new(); 256];
        let mut decode_map: HashMap<u32, u8> = HashMap::new();

        for byte_val in 0..256usize {
            let target_grid = &shuffled_grids[byte_val];

            for positions in &combinations {
                // 获取提示：每个位置的值
                let raw_parts: [(u8, u8); 4] = [
                    (target_grid[positions[0]], positions[0] as u8),
                    (target_grid[positions[1]], positions[1] as u8),
                    (target_grid[positions[2]], positions[2] as u8),
                    (target_grid[positions[3]], positions[3] as u8),
                ];

                // 检查唯一性：这 4 个提示是否唯一确定目标网格
                let mut match_count = 0;
                for g in &all_grids {
                    let mut matches = true;
                    for &(val, pos) in &raw_parts {
                        if g[pos as usize] != val {
                            matches = false;
                            break;
                        }
                    }
                    if matches {
                        match_count += 1;
                        if match_count > 1 {
                            break;
                        }
                    }
                }

                if match_count == 1 {
                    // 唯一确定！编码提示字节
                    let mut hints = [0u8; 4];
                    for (i, &(val, pos)) in raw_parts.iter().enumerate() {
                        hints[i] = layout.encode_hint(val - 1, pos); // val: 1..4 → 0..3
                    }

                    encode_table[byte_val].push(hints);
                    let key = pack_hints_to_key(hints);
                    decode_map.insert(key, byte_val as u8);
                }
            }
        }

        // 验证每个字节至少有一种编码方式
        for (i, encodings) in encode_table.iter().enumerate() {
            if encodings.is_empty() {
                return Err(format!("字节 {} 没有可用编码", i));
            }
        }

        Ok(Table {
            encode_table,
            decode_map,
            padding_pool: layout.padding_pool.clone(),
            layout,
        })
    }

    /// 编码单个字节，随机选择一种编码方式
    pub fn encode_byte(&self, b: u8, rng: &mut impl rand::Rng) -> [u8; 4] {
        let encodings = &self.encode_table[b as usize];
        let idx = rng.gen_range(0..encodings.len());
        encodings[idx]
    }

    /// 解码 4 个排序后的提示字节
    pub fn decode_hints(&self, hints: [u8; 4]) -> Option<u8> {
        let key = pack_hints_to_key(hints);
        self.decode_map.get(&key).copied()
    }

    /// 获取随机 padding 字节
    pub fn random_padding(&self, rng: &mut impl rand::Rng) -> u8 {
        let idx = rng.gen_range(0..self.padding_pool.len());
        self.padding_pool[idx]
    }
}

/// 将 4 个提示排序后打包为 u32 键
pub fn pack_hints_to_key(mut hints: [u8; 4]) -> u32 {
    // 排序网络（4 元素冒泡排序展开）
    if hints[0] > hints[1] {
        hints.swap(0, 1);
    }
    if hints[2] > hints[3] {
        hints.swap(2, 3);
    }
    if hints[0] > hints[2] {
        hints.swap(0, 2);
    }
    if hints[1] > hints[3] {
        hints.swap(1, 3);
    }
    if hints[1] > hints[2] {
        hints.swap(1, 2);
    }

    (hints[0] as u32) << 24 | (hints[1] as u32) << 16 | (hints[2] as u32) << 8 | hints[3] as u32
}

/// 生成 C(n, k) 组合
fn generate_combinations(n: usize, k: usize) -> Vec<Vec<usize>> {
    let mut result = Vec::new();
    let mut current = Vec::with_capacity(k);
    combine(0, n, k, &mut current, &mut result);
    result
}

fn combine(
    start: usize,
    n: usize,
    k: usize,
    current: &mut Vec<usize>,
    result: &mut Vec<Vec<usize>>,
) {
    if k == 0 {
        result.push(current.clone());
        return;
    }
    for i in start..=(n - k) {
        current.push(i);
        combine(i + 1, n, k - 1, current, result);
        current.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_builds_successfully() {
        let table = Table::new("test-key", "prefer_ascii", "").unwrap();
        // 每个字节都应该有至少一种编码
        for (i, enc) in table.encode_table.iter().enumerate() {
            assert!(!enc.is_empty(), "字节 {} 没有编码", i);
        }
    }

    #[test]
    fn encode_decode_roundtrip_ascii() {
        let table = Table::new("test-key-roundtrip", "prefer_ascii", "").unwrap();
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        for byte_val in 0..=255u8 {
            let hints = table.encode_byte(byte_val, &mut rng);
            let decoded = table.decode_hints(hints);
            assert_eq!(decoded, Some(byte_val), "字节 {} 编解码不一致", byte_val);
        }
    }

    #[test]
    fn encode_decode_roundtrip_entropy() {
        let table = Table::new("test-key-entropy", "prefer_entropy", "").unwrap();
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        for byte_val in 0..=255u8 {
            let hints = table.encode_byte(byte_val, &mut rng);
            let decoded = table.decode_hints(hints);
            assert_eq!(decoded, Some(byte_val), "字节 {} 编解码不一致", byte_val);
        }
    }

    #[test]
    fn combinations_count() {
        let combos = generate_combinations(16, 4);
        assert_eq!(combos.len(), 1820); // C(16,4) = 1820
    }

    #[test]
    fn pack_hints_order_independent() {
        let a = pack_hints_to_key([0x41, 0x52, 0x63, 0x74]);
        let b = pack_hints_to_key([0x74, 0x63, 0x52, 0x41]);
        let c = pack_hints_to_key([0x52, 0x41, 0x74, 0x63]);
        assert_eq!(a, b);
        assert_eq!(b, c);
    }
}
