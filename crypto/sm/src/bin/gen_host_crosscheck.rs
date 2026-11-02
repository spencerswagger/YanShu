//! 生成**宿主侧对照请求**：`vectors/host-crosscheck.json`（机器可读）+ `.md`（人读表格）。
//!
//! ```text
//! cargo run --release --bin gen-host-crosscheck -- ../vectors
//! ```
//!
//! 每条都给出：稳定 id、算法、全部输入（key/nonce/aad/plaintext/pub/priv/k）、
//! 期望输出长度与编码、本实现算出的 `expected_hex`、以及口径备注。
//! `tool_requirement` 指明复算工具：`openssl` 能直接做 / 需要 `openssl` 库（CLI 不支持 AEAD）/
//! 必须 GmSSL（固定 k 的 SM2、整包逐字节）。

use std::fs;
use std::path::{Path, PathBuf};

use yanshu_sm::bigint::U256;
use yanshu_sm::der;
use yanshu_sm::gcm;
use yanshu_sm::hkdf::hkdf_sm3;
use yanshu_sm::pack::{self, v1, PackInput, PackParams};
use yanshu_sm::sm2;
use yanshu_sm::sm3::{hmac_sm3, sm3};

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

fn hexs(b: &[u8]) -> String {
    format!("\"{}\"", hex(b))
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

fn arr32(s: &str) -> [u8; 32] {
    let v = unhex(s);
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

fn arr16(s: &str) -> [u8; 16] {
    let v = unhex(s);
    let mut a = [0u8; 16];
    a.copy_from_slice(&v);
    a
}

fn arr65(s: &str) -> [u8; 65] {
    let v = unhex(s);
    let mut a = [0u8; 65];
    a.copy_from_slice(&v);
    a
}

fn u256(s: &str) -> U256 {
    U256::from_be_bytes(&arr32(s))
}

struct Entry {
    id: &'static str,
    algo: &'static str,
    fields: String, // 已格式化的额外 JSON 字段（key/pub/priv/nonce/...）
    expected_len: usize,
    expected_encoding: &'static str,
    expected_hex: String,
    tool: &'static str,
    mode: &'static str,
    note: &'static str,
}

fn entry_into(out: &mut Vec<Entry>, e: Entry) {
    out.push(e);
}

/// 契约 §15.1 夹具
const PB_R: &str = "0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13";
const D_S: &str = "00c1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f";
const PB_S: &str = "04bfd9df73290f50ec16bd184e31c043b6d70fcfd245f76d10ef26b66c9d19b116f425afea1e7e849b2f573e562abab65cf47c045c32a2ecc2f23f86519a1ec25d";
const DK: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const KDF_SALT: &str = "000102030405060708090a0b0c0d0e0f";
const K_ENC: &str = "59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21";
const K_SIG: &str = "6cb28d99385c175c94f94e934817663fc176d925dd72b727260dbaae1fb2f96f";

fn sign_der(priv_hex: &str, msg: &[u8], k_hex: &str) -> Vec<u8> {
    let sk = arr32(priv_hex);
    let raw = sm2::sign_with_k(&sk, msg, sm2::DEFAULT_ID, &u256(k_hex))
        .expect("sign")
        .expect("k usable");
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&raw[..32]);
    s.copy_from_slice(&raw[32..]);
    der::encode_signature(&r, &s)
}

fn main() {
    let out_dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("../vectors"));
    let _ = fs::create_dir_all(&out_dir);

    let mut entries: Vec<Entry> = Vec::new();

    // ---------------- SM3
    let sm3_cases: Vec<(&'static str, Vec<u8>, &'static str)> = vec![
        ("sm3-001", Vec::new(), "空串"),
        ("sm3-002", vec![0x00], "1 字节 0x00"),
        ("sm3-003", b"abc".to_vec(), "标准 abc"),
        (
            "sm3-004",
            "雁书：一次可信的传输".as_bytes().to_vec(),
            "中文 UTF-8（14 个汉字 + 标点）",
        ),
    ];
    for (id, msg, note) in sm3_cases {
        let digest = sm3(&msg);
        entry_into(
            &mut entries,
            Entry {
                id,
                algo: "SM3",
                fields: format!("\"plaintext\": {}", hexs(&msg)),
                expected_len: 32,
                expected_encoding: "hex",
                expected_hex: hex(&digest),
                tool: "openssl",
                mode: "byte-exact",
                note,
            },
        );
    }

    // 1 MiB（只给摘要）
    let big: Vec<u8> = (0..(1024 * 1024)).map(|i| (i * 31 + 7) as u8).collect();
    entry_into(
        &mut entries,
        Entry {
            id: "sm3-005",
            algo: "SM3",
            fields: "\"plaintext\": null, \"plaintext_len\": 1048576, \"plaintext_rule\": \"byte[i] = (i*31 + 7) & 0xff, i = 0..1048575\"".to_string(),
            expected_len: 32,
            expected_encoding: "hex",
            expected_hex: hex(&sm3(&big)),
            tool: "openssl",
            mode: "byte-exact",
            note: "1 MiB 数据只给摘要与生成规则（不塞全文）",
        },
    );

    // ---------------- HMAC-SM3（HKDF 依赖它）
    let hk = hmac_sm3(b"key", b"The quick brown fox jumps over the lazy dog");
    entry_into(
        &mut entries,
        Entry {
            id: "hmac-001",
            algo: "HMAC-SM3",
            fields: "\"key\": \"6b6579\", \"plaintext\": \"54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67\"".to_string(),
            expected_len: 32,
            expected_encoding: "hex",
            expected_hex: hex(&hk),
            tool: "openssl",
            mode: "byte-exact",
            note: "HMAC 块长 64；OpenSSL 3.x 用 -mac HMAC -digest SM3",
        },
    );

    // ---------------- HKDF-SM3（契约 §11）
    let mut kek_c = [0u8; 16];
    hkdf_sm3(&arr16(KDF_SALT), &arr32(DK), v1::KDF_INFO_CHUNK, &mut kek_c);
    entry_into(
        &mut entries,
        Entry {
            id: "hkdf-001",
            algo: "HKDF-SM3",
            fields: format!("\"ikm\": \"{}\", \"salt\": \"{}\", \"info\": \"{}\", \"info_text\": \"YANSHU/v1/chunk-key\"", DK, KDF_SALT, hex(v1::KDF_INFO_CHUNK)),
            expected_len: 16,
            expected_encoding: "hex",
            expected_hex: hex(&kek_c),
            tool: "openssl-lib",
            mode: "byte-exact",
            note: "RFC 5869 结构，PRF=HMAC-SM3；OpenSSL CLI 无 HKDF-SM3 子命令，需 EVP_KDF 或脚本",
        },
    );
    let mut kek_m = [0u8; 16];
    hkdf_sm3(
        &arr16(KDF_SALT),
        &arr32(DK),
        v1::KDF_INFO_MANIFEST,
        &mut kek_m,
    );
    entry_into(
        &mut entries,
        Entry {
            id: "hkdf-002",
            algo: "HKDF-SM3",
            fields: format!("\"ikm\": \"{}\", \"salt\": \"{}\", \"info\": \"{}\", \"info_text\": \"YANSHU/v1/manifest-key\"", DK, KDF_SALT, hex(v1::KDF_INFO_MANIFEST)),
            expected_len: 16,
            expected_encoding: "hex",
            expected_hex: hex(&kek_m),
            tool: "openssl-lib",
            mode: "byte-exact",
            note: "同 hkdf-001，info 换成清单密钥",
        },
    );

    // ---------------- SM4-GCM
    struct G {
        id: &'static str,
        key: [u8; 16],
        nonce: [u8; 12],
        aad: Vec<u8>,
        pt: Vec<u8>,
        note: &'static str,
    }
    let chunk0_aad = {
        let mut h = [0u8; 32];
        h[0] = 1;
        h[1..5].copy_from_slice(b"YSPK");
        h[5] = 1;
        h[6] = 0;
        h[7..11].copy_from_slice(&1_048_576u32.to_be_bytes());
        h[11..15].copy_from_slice(&1u32.to_be_bytes());
        h[15..23].copy_from_slice(&5u64.to_be_bytes());
        h[27] = 1;
        h[28..32].copy_from_slice(&5u32.to_be_bytes());
        h.to_vec()
    };
    let cases = vec![
        G {
            id: "sm4gcm-001",
            key: [0u8; 16],
            nonce: [0u8; 12],
            aad: Vec::new(),
            pt: Vec::new(),
            note: "空明文 / 零 key / 零 nonce / 无 AAD",
        },
        G {
            id: "sm4gcm-002",
            key: [0x01; 16],
            nonce: [0xAA; 12],
            aad: Vec::new(),
            pt: b"a".to_vec(),
            note: "1 字节明文",
        },
        G {
            id: "sm4gcm-003",
            key: [0x02; 16],
            nonce: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            aad: Vec::new(),
            pt: (0..16).collect(),
            note: "正好一整块 16 字节",
        },
        G {
            id: "sm4gcm-004",
            key: [0x03; 16],
            nonce: [0x5a; 12],
            aad: Vec::new(),
            pt: (0..15).collect(),
            note: "非整块 15 字节",
        },
        G {
            id: "sm4gcm-005",
            key: [0x04; 16],
            nonce: [0x11; 12],
            aad: (0..20).map(|i| (i * 5) as u8).collect(),
            pt: (0..1000).map(|i| (i * 13 + 7) as u8).collect(),
            note: "跨块 1000 字节 + 20 字节 AAD",
        },
        G {
            id: "sm4gcm-006",
            key: [0x05; 16],
            nonce: v1::chunk_nonce(0, true),
            aad: chunk0_aad,
            pt: b"hello".to_vec(),
            note: "契约 §15.2 块 0：真实 AAD_CHUNK(32B) + 块 nonce（末块）",
        },
    ];
    for g in cases {
        let mut ct = vec![0u8; g.pt.len()];
        let mut tag = [0u8; 16];
        gcm::encrypt(&g.key, &g.nonce, &g.aad, &g.pt, &mut ct, &mut tag);
        let mut combined = ct;
        combined.extend_from_slice(&tag);
        entry_into(
            &mut entries,
            Entry {
                id: g.id,
                algo: "SM4-GCM",
                fields: format!(
                    "\"key\": {}, \"nonce\": {}, \"aad\": {}, \"plaintext\": {}",
                    hexs(&g.key),
                    hexs(&g.nonce),
                    hexs(&g.aad),
                    hexs(&g.pt)
                ),
                expected_len: combined.len(),
                expected_encoding: "hex（ciphertext ‖ tag，tag 为末尾 16 字节）",
                expected_hex: hex(&combined),
                tool: "gmssl-cli",
                mode: "byte-exact",
                note: g.note,
            },
        );
    }

    // ---------------- SM2 加密（固定 k）
    let pb_r = arr65(PB_R);
    let enc_cases = vec![
        (
            "sm2-enc-001",
            PB_R,
            DK,
            K_ENC,
            "契约 §15.1 夹具：封装 32 字节 DK（长度必须 32）",
        ),
        (
            "sm2-enc-002",
            PB_S,
            "00",
            "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
            "1 字节边界（每个实现都应支持的最小长度）",
        ),
    ];
    for (id, pub_hex, pt_hex, k_hex, note) in enc_cases {
        let pub65 = arr65(pub_hex);
        let pub64: [u8; 64] = pub65[1..].try_into().unwrap();
        let ct = sm2::encrypt(&pub64, &unhex(pt_hex), &u256(k_hex)).expect("encrypt");
        let mut with_prefix = vec![0x04u8];
        with_prefix.extend_from_slice(&ct);
        entry_into(
            &mut entries,
            Entry {
                id,
                algo: "SM2-encrypt",
                fields: format!(
                    "\"pub\": {}, \"k\": \"{}\", \"plaintext\": {}",
                    hexs(&pub65),
                    k_hex,
                    hexs(&unhex(pt_hex))
                ),
                expected_len: with_prefix.len(),
                expected_encoding: "hex（0x04 ‖ C1.x(32) ‖ C1.y(32) ‖ C3(32) ‖ C2）",
                expected_hex: hex(&with_prefix),
                tool: "gmssl-lib",
                mode: "byte-exact-with-fixed-k",
                note,
            },
        );
    }
    let _ = pb_r;

    // ---------------- SM2 签名（固定 k；YSAUTH1 / YSSIG1）
    let mut auth_inputs: Vec<(&'static str, Vec<u8>, &'static str)> = Vec::new();
    // REGISTER：YSAUTH1 | 01 | NONCE(32) | CODE(4) | PUBKEY(65)
    let nonce: Vec<u8> = (0u8..32).collect();
    let mut reg = b"YSAUTH1".to_vec();
    reg.push(0x01);
    reg.extend_from_slice(&nonce);
    reg.extend_from_slice(b"AWQW");
    reg.extend_from_slice(&arr65(PB_S));
    auth_inputs.push(("sm2-sign-001", reg, "API §1.3 REGISTER（CODE=AWQW）"));

    // TRANSFER_CREATE：YSAUTH1|03|NONCE|SENDER_CODE|RECIPIENT_CODE|size|chunk|count|prelude_len|prelude_sm3
    let mut tc = b"YSAUTH1".to_vec();
    tc.push(0x03);
    tc.extend_from_slice(&nonce);
    tc.extend_from_slice(b"AWQW");
    tc.extend_from_slice(b"WTJF");
    tc.extend_from_slice(&5u64.to_be_bytes());
    tc.extend_from_slice(&1_048_576u32.to_be_bytes());
    tc.extend_from_slice(&1u32.to_be_bytes());
    tc.extend_from_slice(&485u32.to_be_bytes());
    tc.extend_from_slice(&{
        // prelude_sm3 用契约 §15.2 的 prelude 前 485 字节的 SM3
        let full_hex = contract_v1_pack();
        let full = unhex(&full_hex);
        sm3(&full[..485])
    });
    auth_inputs.push((
        "sm2-sign-002",
        tc,
        "API §1.3 TRANSFER_CREATE（prelude_sm3 取契约 §15.2 的 prelude）",
    ));

    // NICKNAME_UPDATE：YSAUTH1|02|NONCE|CODE|u16 len|nick
    let nick = "雁书用户".as_bytes();
    let mut nu = b"YSAUTH1".to_vec();
    nu.push(0x02);
    nu.extend_from_slice(&nonce);
    nu.extend_from_slice(b"AWQW");
    nu.extend_from_slice(&(nick.len() as u16).to_be_bytes());
    nu.extend_from_slice(nick);
    auth_inputs.push(("sm2-sign-003", nu, "API §1.3 NICKNAME_UPDATE（昵称 UTF-8）"));

    // 包签名 YSSIG1：契约 §15.5
    let v1pack_hex = contract_v1_pack();
    let v1pack = unhex(&v1pack_hex);
    let man_off = 112 + 65 + 129;
    let man_len = 109;
    let mut sig_input = b"YSSIG1".to_vec();
    sig_input.extend_from_slice(&[1, 0]);
    sig_input.extend_from_slice(&v1pack[..72]);
    sig_input.extend_from_slice(&v1pack[112..177]);
    sig_input.extend_from_slice(&v1pack[man_off..man_off + man_len]);
    auth_inputs.push((
        "sm2-sign-004",
        sig_input,
        "契约 §10.2 包签名 SIG_INPUT（YSSIG1，§15.5 样例）",
    ));

    for (id, msg, note) in auth_inputs {
        let sig = sign_der(D_S, &msg, K_SIG);
        entry_into(
            &mut entries,
            Entry {
                id,
                algo: "SM2-sign",
                fields: format!(
                    "\"priv\": \"{}\", \"pub\": {}, \"k\": \"{}\", \"sig_input\": {}, \"sig_input_len\": {}",
                    D_S,
                    hexs(&arr65(PB_S)),
                    K_SIG,
                    hexs(&msg),
                    msg.len()
                ),
                expected_len: sig.len(),
                expected_encoding: "DER（SEQUENCE{r,s}，70..72 字节）",
                expected_hex: hex(&sig),
                tool: "gmssl-lib",
                mode: "byte-exact-with-fixed-k",
                note,
            },
        );
    }

    // ---------------- YSPK/1.0 整包
    let v1_pack = contract_v1_pack();
    entry_into(
        &mut entries,
        Entry {
            id: "yspk-v1-min",
            algo: "YSPK/1.0 pack",
            fields: pack_fields("hello", 1_048_576, "hi.txt", "text/plain", "txt", true),
            expected_len: v1_pack.len() / 2,
            expected_encoding: "hex（完整包字节）",
            expected_hex: v1_pack.clone(),
            tool: "gmssl-lib",
            mode: "byte-exact-with-fixed-k",
            note: "契约 §15.2 最小单块包（522 字节），已逐字节核对",
        },
    );

    let v2_pack = contract_v2_pack();
    entry_into(
        &mut entries,
        Entry {
            id: "yspk-v1-multi",
            algo: "YSPK/1.0 pack",
            fields: pack_fields_multi(),
            expected_len: v2_pack.len() / 2,
            expected_encoding: "hex（完整包字节）",
            expected_hex: v2_pack.clone(),
            tool: "gmssl-lib",
            mode: "byte-exact-with-fixed-k",
            note: "契约 §15.3 多块包（CHUNK_SIZE=32，3 块，743 字节），已逐字节核对",
        },
    );

    // ---------------- 写 JSON
    let mut json = String::new();
    json.push_str("{\n");
    json.push_str("  \"meta\": {\n");
    json.push_str("    \"contract\": \"docs/CRYPTO-PACK.md v1（YSPK/1.0）\",\n");
    json.push_str("    \"api_contract\": \"docs/API.md §1.3（SIG_INPUT / YSAUTH1）\",\n");
    json.push_str("    \"generated_by\": \"yanshu-sm gen-host-crosscheck\",\n");
    json.push_str(&format!("    \"entries\": {},\n", entries.len()));
    json.push_str("    \"encoding\": \"全部 hex 小写、无 0x 前缀；整数大端\",\n");
    json.push_str("    \"how_to_use\": \"按 conventions 复算每条，把结果与 expected_hex 逐字节比；不一致时先查字节序/AAD 字段顺序/KDF info\",\n");
    json.push_str("    \"tool_legend\": {\n");
    json.push_str("      \"openssl\": \"OpenSSL 3.5.7 命令行可直接算（SM3 / HMAC）\",\n");
    json.push_str(
        "      \"openssl-lib\": \"需要 OpenSSL 库（EVP_KDF 等），CLI 子命令不足以完成\",\n",
    );
    json.push_str("      \"gmssl-cli\": \"需要 GmSSL 命令行（gmssl sm4 -gcm），OpenSSL CLI 的 enc 不支持 AEAD\",\n");
    json.push_str("      \"gmssl-lib\": \"必须 GmSSL 库（可固定 k）才能逐字节；OpenSSL 只能做解密/验签方向\"\n");
    json.push_str("    }\n");
    json.push_str("  },\n  \"entries\": [\n");

    for (i, e) in entries.iter().enumerate() {
        json.push_str("    {\n");
        json.push_str(&format!("      \"id\": \"{}\",\n", e.id));
        json.push_str(&format!("      \"algo\": \"{}\",\n", e.algo));
        json.push_str(&format!("      {},\n", e.fields));
        json.push_str(&format!("      \"expected_len\": {},\n", e.expected_len));
        json.push_str(&format!(
            "      \"expected_encoding\": \"{}\",\n",
            e.expected_encoding
        ));
        json.push_str(&format!(
            "      \"expected_hex\": \"{}\",\n",
            e.expected_hex
        ));
        json.push_str(&format!("      \"tool_requirement\": \"{}\",\n", e.tool));
        json.push_str(&format!("      \"verify_mode\": \"{}\",\n", e.mode));
        json.push_str(&format!("      \"note\": \"{}\"\n", e.note));
        json.push_str(if i + 1 == entries.len() {
            "    }\n"
        } else {
            "    },\n"
        });
    }
    json.push_str("  ]\n}\n");

    let json_path = out_dir.join("host-crosscheck.json");
    fs::write(&json_path, &json).expect("write json");

    // ---------------- 写 Markdown
    let mut md = String::new();
    md.push_str("# 宿主侧对照请求（YSPK/1.0）\n\n");
    md.push_str(
        "> 由 `cargo run --release --bin gen-host-crosscheck` 生成，值与仓库内实现同源。\n",
    );
    md.push_str("> 机器可读版本：`vectors/host-crosscheck.json`（同目录）。\n\n");
    md.push_str(&format!(
        "共 **{} 条**。全部 hex 小写、无 `0x`，整数大端。\n\n",
        entries.len()
    ));
    md.push_str("## 工具能力对照\n\n");
    md.push_str("| tool_requirement | 含义 |\n|---|---|\n");
    md.push_str("| `openssl` | OpenSSL 3.5.7 命令行直接可算 |\n");
    md.push_str("| `openssl-lib` | 需要 OpenSSL 库（如 EVP_KDF / EVP AEAD），CLI 不够 |\n");
    md.push_str(
        "| `gmssl-cli` | 需要 GmSSL 命令行（`gmssl sm4 -gcm`；OpenSSL 的 `enc` 不支持 AEAD） |\n",
    );
    md.push_str(
        "| `gmssl-lib` | **必须 GmSSL 库**：要固定 k 才能逐字节；OpenSSL 只能做解密/验签方向 |\n\n",
    );
    md.push_str("## 清单\n\n");
    md.push_str("| id | algo | 输入要点 | 期望长度 | 编码 | 工具 | 备注 |\n|---|---|---|---:|---|---|---|\n");
    for e in &entries {
        let brief = brief_fields(&e.fields);
        md.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | `{}` | {} |\n",
            e.id, e.algo, brief, e.expected_len, e.expected_encoding, e.tool, e.note
        ));
    }
    md.push_str("\n## 需要 GmSSL（OpenSSL 不够）的条目\n\n");
    md.push_str("| id | 为什么 |\n|---|---|\n");
    for e in &entries {
        if e.tool == "gmssl-lib" || e.tool == "gmssl-cli" {
            md.push_str(&format!("| `{}` | {} |\n", e.id, why_gmssl(e.tool)));
        }
    }
    md.push_str("\nOpenSSL 能独立完成的部分：`sm3-*`、`hmac-001`；`hkdf-*` 需要 OpenSSL 库里的 HKDF（EVP_KDF）；");
    md.push_str(
        "SM4-GCM 用 OpenSSL 库（EVP_EncryptInit_ex + EVP_CTRL_GCM_GET_TAG）也可以，CLI 不行。\n",
    );

    let md_path = out_dir.join("host-crosscheck.md");
    fs::write(&md_path, md).expect("write md");
    eprintln!(
        "wrote {} ({} entries) and {}",
        json_path.display(),
        entries.len(),
        md_path.display()
    );
    let _ = Path::new("");
}

fn why_gmssl(tool: &str) -> &'static str {
    match tool {
        "gmssl-lib" => "需要固定 k 才能逐字节；OpenSSL 的 SM2 每次随机 k，只能解密/验签",
        "gmssl-cli" => "OpenSSL CLI 的 enc 不支持 GCM；GmSSL 命令行 `sm4 -gcm` 可以直接出密文+tag",
        _ => "",
    }
}

fn brief_fields(fields: &str) -> String {
    let mut s = String::new();
    for part in fields.split("\", \"") {
        let key = part
            .split(':')
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches('"');
        if key.is_empty() {
            continue;
        }
        if !s.is_empty() {
            s.push_str("; ");
        }
        s.push_str(key);
    }
    s
}

fn pack_fields(
    data: &str,
    chunk_size: u32,
    name: &str,
    mime: &str,
    ext: &str,
    contract: bool,
) -> String {
    format!(
        "\"recipient_pub\": \"{}\", \"sender_priv\": \"{}\", \"dk\": \"{}\", \"kdf_salt\": \"{}\", \"k_enc\": \"{}\", \"k_sig\": \"{}\", \"created_at_ms\": 1767225600000, \"chunk_size\": {}, \"file_name\": \"{}\", \"mime\": \"{}\", \"ext\": \"{}\", \"plaintext\": {}",
        PB_R,
        D_S,
        DK,
        KDF_SALT,
        K_ENC,
        K_SIG,
        chunk_size,
        name,
        mime,
        ext,
        hexs(data.as_bytes())
    )
    .replace("true", if contract { "true" } else { "false" })
}

fn pack_fields_multi() -> String {
    let data: Vec<u8> = (0u8..0x50).collect();
    format!(
        "\"recipient_pub\": \"{}\", \"sender_priv\": \"{}\", \"dk\": \"{}\", \"kdf_salt\": \"{}\", \"k_enc\": \"{}\", \"k_sig\": \"{}\", \"created_at_ms\": 1767225600000, \"chunk_size\": 32, \"file_name\": \"multi.bin\", \"mime\": \"application/octet-stream\", \"ext\": \"bin\", \"plaintext\": {}, \"plaintext_len\": 80",
        PB_R, D_S, DK, KDF_SALT, K_ENC, K_SIG, hexs(&data)
    )
}

fn fixture_params() -> PackParams {
    PackParams {
        dk: arr32(DK),
        kdf_salt: arr16(KDF_SALT),
        k_enc: u256(K_ENC),
        k_sig: u256(K_SIG),
    }
}

fn contract_v1_pack() -> String {
    let recipient = arr65(PB_R);
    let sender = arr32(D_S);
    let input = PackInput {
        recipient_public: &recipient,
        sender_private: &sender,
        name: "hi.txt",
        mime: "text/plain",
        ext: "txt",
        created_at_ms: 1_767_225_600_000,
        chunk_size: 1_048_576,
        data: b"hello",
    };
    hex(&pack::pack_with(&input, &fixture_params()).expect("pack"))
}

fn contract_v2_pack() -> String {
    let recipient = arr65(PB_R);
    let sender = arr32(D_S);
    let data: Vec<u8> = (0u8..0x50).collect();
    let input = PackInput {
        recipient_public: &recipient,
        sender_private: &sender,
        name: "multi.bin",
        mime: "application/octet-stream",
        ext: "bin",
        created_at_ms: 1_767_225_600_000,
        chunk_size: 32,
        data: &data,
    };
    hex(&pack::pack_with(&input, &fixture_params()).expect("pack"))
}
