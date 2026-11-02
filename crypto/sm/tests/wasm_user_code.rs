//! wasm 与原生算码一致（P0 锁死）。
//!
//! 原生侧由 `tests/ffi_user_code.rs` 调 FFI 函数断言；这里再拿**实际 wasm 产物**
//! 跑一遍（Node 加载，0 import）。wasm 产物缺失时跳过并打印提示——CI 里
//! `scripts/wasm-smoke/smoke.mjs` 会在构建后强制跑同一份向量。

use std::path::PathBuf;
use std::process::Command;

fn wasm_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("YS_WASM") {
        let p = PathBuf::from(p);
        return p.exists().then_some(p);
    }
    let target = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "../target".into());
    let p = PathBuf::from(target).join("wasm32-unknown-unknown/release/yanshu_sm.wasm");
    p.exists().then_some(p)
}

#[test]
fn wasm_user_code_matches_native() {
    let Some(wasm) = wasm_path() else {
        eprintln!(
            "skip: wasm 产物不存在（先 cargo build --release --target wasm32-unknown-unknown）"
        );
        return;
    };
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let script = here.join("../../scripts/wasm-smoke/user-code-check.mjs");
    let vectors = here.join("../../vectors/user-code-vectors.json");
    if !script.exists() || !vectors.exists() {
        eprintln!("skip: 缺少 user-code-check.mjs 或向量文件");
        return;
    }

    let out = Command::new("node")
        .arg(&script)
        .arg(&wasm)
        .arg(&vectors)
        .output()
        .expect("run node");
    assert!(
        out.status.success(),
        "node 退出码 {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let mut code_checked = 0;
    let mut norm_checked = 0;
    let mut saw_pb_s = false;

    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts.first().copied() {
            Some("C") => {
                // C name code64 code65 check64 check65 expectCode expectCheck
                assert_eq!(parts.len(), 8, "C 行格式: {}", line);
                let (name, c64, c65, k64, k65, want, want_check) = (
                    parts[1], parts[2], parts[3], parts[4], parts[5], parts[6], parts[7],
                );
                assert_eq!(c64, want, "{}: ys_user_code(64B) 与原生不一致", name);
                assert_eq!(c65, want, "{}: ys_user_code_wire(65B) 与原生不一致", name);
                assert_eq!(k64, want_check, "{}: check_symbol(64B) 不一致", name);
                assert_eq!(k65, want_check, "{}: check_symbol_wire(65B) 不一致", name);
                if name == "contract_pb_s" {
                    assert_eq!(want, "AWQW", "契约 PB_S 必须得到 AWQW");
                    saw_pb_s = true;
                }
                code_checked += 1;
            }
            Some("N") => {
                // N ok rc in_hex got_hex expect_hex
                assert_eq!(parts.len(), 6, "N 行格式: {}", line);
                let ok = parts[1] == "1";
                let rc: i32 = parts[2].parse().expect("rc");
                let input = if parts[3] == "-" {
                    String::new()
                } else {
                    String::from_utf8(
                        (0..parts[3].len() / 2)
                            .map(|i| u8::from_str_radix(&parts[3][i * 2..i * 2 + 2], 16).unwrap())
                            .collect(),
                    )
                    .expect("utf8")
                };
                if ok {
                    let got = hex_to_string(parts[4]);
                    let want = hex_to_string(parts[5]);
                    assert_eq!(rc, 0, "合法输入 {:?} 在 wasm 下失败", input);
                    assert_eq!(got, want, "normalize 在 wasm 与原生不一致: {:?}", input);
                } else {
                    assert!(
                        rc < 0,
                        "非法输入 {:?} 在 wasm 下竟然成功（rc={}）",
                        input,
                        rc
                    );
                }
                norm_checked += 1;
            }
            Some("E") => panic!("node 侧出错: {}", line),
            _ => {}
        }
    }

    assert!(saw_pb_s, "向量里必须有契约 PB_S 条目");
    assert!(
        code_checked >= 5,
        "至少校验 5 组公钥，实际 {}",
        code_checked
    );
    assert!(
        norm_checked >= 20,
        "归一化向量至少 20 条，实际 {}",
        norm_checked
    );
}

fn hex_to_string(hex: &str) -> String {
    if hex == "-" {
        return String::new();
    }
    String::from_utf8(
        (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect(),
    )
    .expect("utf8")
}
