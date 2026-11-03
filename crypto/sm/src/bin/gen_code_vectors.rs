//! 生成归一化测试向量：`testdata/normalize-vectors.json`。
//!
//! ```text
//! cargo run --release --bin gen-code-vectors -- ../testdata/normalize-vectors.json
//! ```
//! 数据源是 `yanshu_sm::code::NORMALIZE_VECTORS`（与单元测试同一张表），保证两边同源。

use std::fs;
use std::path::PathBuf;

use yanshu_sm::code::{normalize, NORMALIZE_VECTORS};

fn esc(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("../testdata/normalize-vectors.json"));

    let mut json = String::new();
    json.push_str("{\n");
    json.push_str("  \"rule\": \"丢弃 - 空格 TAB CR LF；其余转大写后 O→0、I→1、L→1；结果必须全在 0123456789ABCDEFGHJKMNPQRSTVWXYZ 且恰好 4 位（不足不补齐、超过不截断）；失败 CRYPTO_CODE_INVALID；幂等\",\n");
    json.push_str("  \"alphabet\": \"0123456789ABCDEFGHJKMNPQRSTVWXYZ\",\n");
    json.push_str("  \"idempotent\": true,\n");
    json.push_str("  \"vectors\": [\n");
    for (i, (input, expected)) in NORMALIZE_VECTORS.iter().enumerate() {
        // 自检：表与实现必须一致，且成功结果幂等
        match expected {
            Some(want) => {
                let got = normalize(input).expect("vector should be accepted");
                assert_eq!(&got, want, "vector {:?}", input);
                assert_eq!(normalize(&got).unwrap(), got, "idempotency {:?}", input);
                json.push_str(&format!(
                    "    {{\"in\": \"{}\", \"out\": \"{}\", \"ok\": true, \"idempotent\": true}}{}\n",
                    esc(input),
                    esc(want),
                    if i + 1 == NORMALIZE_VECTORS.len() { "" } else { "," }
                ));
            }
            None => {
                assert!(
                    normalize(input).is_err(),
                    "vector {:?} should be rejected",
                    input
                );
                json.push_str(&format!(
                    "    {{\"in\": \"{}\", \"out\": null, \"ok\": false, \"error\": \"CRYPTO_CODE_INVALID\"}}{}\n",
                    esc(input),
                    if i + 1 == NORMALIZE_VECTORS.len() { "" } else { "," }
                ));
            }
        }
    }
    json.push_str("  ]\n}\n");
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    fs::write(&path, json).expect("write normalize vectors");
    eprintln!(
        "wrote {} ({} vectors)",
        path.display(),
        NORMALIZE_VECTORS.len()
    );
}
