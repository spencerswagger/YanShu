//! 用户码跨实现向量：`vectors/user-code-vectors.json`
//!
//! ```text
//! cargo run --release --bin gen-user-code-vectors -- ../vectors
//! ```
//! 每条给 `pub65`（wire）、`code`、`check`；`wasm` 与原生必须同值
//! （`scripts/wasm-smoke/smoke.mjs` 会同时调 64 入参与 65 入参两个导出）。

use std::fs;
use std::path::PathBuf;

use yanshu_sm::code;
use yanshu_sm::sm2;
use yanshu_sm::sm3::sm3;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn priv_of(label: &str) -> [u8; 32] {
    let mut d = sm3(label.as_bytes());
    d[0] = 0;
    d[1] &= 0x7f;
    d
}

fn pub65(pub64: &[u8; 64]) -> [u8; 65] {
    let mut p = [0u8; 65];
    p[0] = 0x04;
    p[1..].copy_from_slice(pub64);
    p
}

fn main() {
    let out_dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("../vectors"));
    let _ = fs::create_dir_all(&out_dir);

    let mut entries: Vec<(String, [u8; 65], String, char)> = Vec::new();
    // 1) 契约样例
    let contract = "04bfd9df73290f50ec16bd184e31c043b6d70fcfd245f76d10ef26b66c9d19b116f425afea1e7e849b2f573e562abab65cf47c045c32a2ecc2f23f86519a1ec25d";
    let mut p = [0u8; 65];
    for i in 0..65 {
        p[i] = u8::from_str_radix(&contract[i * 2..i * 2 + 2], 16).unwrap();
    }
    entries.push((
        "contract_pb_s".into(),
        p,
        code::from_public_key(&p),
        code::check_symbol(&p),
    ));

    // 2) 四组派生密钥
    for label in [
        "yanshu-key-alice",
        "yanshu-key-bob",
        "yanshu-key-carol",
        "yanshu-core-signer",
    ] {
        let d = priv_of(label);
        let pk = pub65(&sm2::public_from_private(&d).expect("pub"));
        entries.push((
            label.to_string(),
            pk,
            code::from_public_key(&pk),
            code::check_symbol(&pk),
        ));
    }

    let mut json = String::new();
    json.push_str("{\n");
    json.push_str("  \"meta\": {\"pubkey\": \"65 字节 wire（0x04‖X‖Y）\", \"code_alphabet\": \"0123456789ABCDEFGHJKMNPQRSTVWXYZ\", \"derivation\": \"Crockford(SM3(pub65))[0..4]\", \"check_symbol\": \"CHECK_ALPHA[first20bit mod 37]，仅 UI 防误，不参与码\"},\n");
    json.push_str("  \"vectors\": [\n");
    for (i, (name, pk, c, chk)) in entries.iter().enumerate() {
        // 自检：64 字节 X‖Y 走同一条派生路径，必须得同值
        let mut x = [0u8; 65];
        x[0] = 0x04;
        x[1..].copy_from_slice(&pk[1..]);
        assert_eq!(code::from_public_key(&x), *c, "{} self-check", name);
        json.push_str(&format!(
            "    {{\"name\": \"{}\", \"pub65\": \"{}\", \"code\": \"{}\", \"check\": \"{}\"}}{}\n",
            name,
            hex(pk),
            c,
            chk,
            if i + 1 == entries.len() { "" } else { "," }
        ));
    }
    json.push_str("  ]\n}\n");

    let path = out_dir.join("user-code-vectors.json");
    fs::write(&path, json).expect("write");
    eprintln!("wrote {} ({} vectors)", path.display(), entries.len());
}
