/// 4x4 Sudoku 网格生成器
///
/// 一个有效的 4x4 数独网格满足：
/// - 每行包含 1..4 各一次
/// - 每列包含 1..4 各一次
/// - 每个 2x2 宫格包含 1..4 各一次
///
/// 总共有 288 个有效的 4x4 数独网格。

/// 4x4 数独网格，16 个位置，每个值为 1..4
pub type Grid = [u8; 16];

/// 回溯法生成全部 288 个有效 4x4 数独网格
pub fn generate_all_grids() -> Vec<Grid> {
    let mut grids = Vec::with_capacity(288);
    let mut g = [0u8; 16];
    backtrack(&mut g, 0, &mut grids);
    grids
}

fn backtrack(g: &mut Grid, idx: usize, grids: &mut Vec<Grid>) {
    if idx == 16 {
        grids.push(*g);
        return;
    }
    let row = idx / 4;
    let col = idx % 4;
    let br = (row / 2) * 2; // 宫格起始行
    let bc = (col / 2) * 2; // 宫格起始列

    for num in 1u8..=4 {
        let mut valid = true;

        // 检查行和列
        for i in 0..4 {
            if g[row * 4 + i] == num || g[i * 4 + col] == num {
                valid = false;
                break;
            }
        }

        // 检查 2x2 宫格
        if valid {
            for r in 0..2 {
                for c in 0..2 {
                    if g[(br + r) * 4 + (bc + c)] == num {
                        valid = false;
                        break;
                    }
                }
                if !valid {
                    break;
                }
            }
        }

        if valid {
            g[idx] = num;
            backtrack(g, idx + 1, grids);
            g[idx] = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_288_grids() {
        let grids = generate_all_grids();
        assert_eq!(grids.len(), 288);
    }

    #[test]
    fn all_grids_are_valid() {
        let grids = generate_all_grids();
        for grid in &grids {
            // 检查每行
            for row in 0..4 {
                let mut seen = [false; 5];
                for col in 0..4 {
                    let v = grid[row * 4 + col] as usize;
                    assert!(v >= 1 && v <= 4);
                    assert!(!seen[v], "行 {} 重复值 {}", row, v);
                    seen[v] = true;
                }
            }
            // 检查每列
            for col in 0..4 {
                let mut seen = [false; 5];
                for row in 0..4 {
                    let v = grid[row * 4 + col] as usize;
                    assert!(!seen[v], "列 {} 重复值 {}", col, v);
                    seen[v] = true;
                }
            }
            // 检查 2x2 宫格
            for br in (0..4).step_by(2) {
                for bc in (0..4).step_by(2) {
                    let mut seen = [false; 5];
                    for r in 0..2 {
                        for c in 0..2 {
                            let v = grid[(br + r) * 4 + (bc + c)] as usize;
                            assert!(!seen[v], "宫格({},{}) 重复值 {}", br, bc, v);
                            seen[v] = true;
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn all_grids_are_unique() {
        let grids = generate_all_grids();
        for i in 0..grids.len() {
            for j in (i + 1)..grids.len() {
                assert_ne!(grids[i], grids[j], "网格 {} 和 {} 重复", i, j);
            }
        }
    }
}
