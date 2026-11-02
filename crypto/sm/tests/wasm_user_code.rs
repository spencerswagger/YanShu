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
    let json = String::from_utf8_lossy(&out.stdout);
    let json = json.trim();

    // 不引 serde：按字段片段做最小校验（够用且无依赖）
    let mut checked = 0;
    for entry in json.split("{\"name\"").skip(1) {
        let code64 = field(entry, "code64");
        let code65 = field(entry, "code65");
        let want = field(entry, "expect_code");
        let check64 = field(entry, "check64");
        let check65 = field(entry, "check65");
        let want_check = field(entry, "expect_check");
        assert_eq!(code64, want, "ys_user_code(64B) 与原生不一致: {}", entry);
        assert_eq!(
            code65, want,
            "ys_user_code_wire(65B) 与原生不一致: {}",
            entry
        );
        assert_eq!(check64, want_check, "check_symbol 不一致: {}", entry);
        assert_eq!(check65, want_check, "check_symbol_wire 不一致: {}", entry);
        checked += 1;
    }
    assert!(checked >= 5, "至少校验 5 组公钥，实际 {}", checked);
    assert!(
        json.contains("\"code64\":\"AWQW\"") || json.contains("\"code64\": \"AWQW\""),
        "契约 PB_S 必须得到 AWQW"
    );
}

fn field<'a>(entry: &'a str, key: &str) -> &'a str {
    let pat = format!("\"{}\":\"", key);
    let i = entry
        .find(&pat)
        .unwrap_or_else(|| panic!("字段 {} 缺失: {}", key, entry));
    let rest = &entry[i + pat.len()..];
    let end = rest.find('"').expect("闭合引号");
    &rest[..end]
}
