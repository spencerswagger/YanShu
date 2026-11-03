//! `ys_normalize_code` 的向量与幂等性（服务端/前端照 `testdata/normalize-vectors.json` 对齐）。

use yanshu_sm::code::{normalize, NORMALIZE_VECTORS};

#[test]
fn vectors_match_and_are_idempotent() {
    assert!(NORMALIZE_VECTORS.len() >= 12, "至少 12 组向量");
    for (input, expected) in NORMALIZE_VECTORS {
        match expected {
            Some(want) => {
                let got = normalize(input)
                    .unwrap_or_else(|e| panic!("输入 {:?} 应被接受，实际 {:?}", input, e));
                assert_eq!(&got, want, "输入 {:?}", input);
                // 幂等：f(f(x)) == f(x)
                assert_eq!(normalize(&got).unwrap(), got, "幂等性失败: {:?}", input);
                // 结果必须是 4 个大写 Crockford 符号
                assert_eq!(got.len(), 4);
                assert!(got.bytes().all(|c| NORMALIZE_ALPHABET.contains(&c)));
            }
            None => {
                assert!(
                    normalize(input).is_err(),
                    "输入 {:?} 应被拒绝（不补齐、不截断、不猜测）",
                    input
                );
            }
        }
    }
}

const NORMALIZE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
