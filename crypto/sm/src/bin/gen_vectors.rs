//! 生成测试向量（全 hex JSON）。
//!
//! 用法（在 `crypto/` 下）：
//! ```text
//! cargo run --release --bin gen-vectors -- ../testdata/vectors.json
//! ```
//! 向量是**确定性**的：密钥、临时标量 k、DK、file_id 全部由固定标签派生，
//! 因此可以在 GmSSL 侧逐字节重算（见 `scripts/crosscheck/`）。

use std::fs;
use std::path::PathBuf;

use yanshu_sm::bigint::U256;
use yanshu_sm::gcm::{self, TAG_SIZE};
use yanshu_sm::hkdf::hkdf_sm3;
use yanshu_sm::pack::{self, layout, PackInput, PackParams};
use yanshu_sm::sm2;
use yanshu_sm::sm3::{hmac_sm3, sm3};

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

fn hex_vec(b: &[u8]) -> String {
    format!("\"{}\"", hex(b))
}

/// 由标签派生一个 < n 的标量（清掉最高字节，保证小于曲线阶 n）。
fn scalar(label: &str) -> U256 {
    let mut d = sm3(label.as_bytes());
    d[0] = 0;
    d[1] &= 0x7f;
    U256::from_be_bytes(&d)
}

fn private_key(label: &str) -> [u8; 32] {
    let mut d = sm3(label.as_bytes());
    d[0] = 0;
    d[1] &= 0x7f;
    d
}

fn main() {
    let out_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("../testdata/vectors.json"));

    let mut json = String::new();
    json.push_str("{\n");
    json.push_str("  \"meta\": {\"suite\": \"SM4-GCM-128/SM3/SM2-C1C3C2\", \"pack_version\": 1, \"id\": \"1234567812345678\"},\n");

    // ---------------- SM3
    json.push_str("  \"sm3\": [\n");
    let sm3_cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("abc", b"abc".to_vec()),
        (
            "abcd_x16",
            b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd".to_vec(),
        ),
        ("bytes_0_63", (0u8..64).collect()),
        (
            "message_1000",
            (0..1000).map(|i| (i * 7 + 3) as u8).collect(),
        ),
    ];
    for (i, (name, msg)) in sm3_cases.iter().enumerate() {
        let digest = sm3(msg);
        json.push_str(&format!(
            "    {{\"name\": \"{}\", \"msg\": {}, \"digest\": {}}}{}\n",
            name,
            hex_vec(msg),
            hex_vec(&digest),
            if i + 1 == sm3_cases.len() { "" } else { "," }
        ));
    }
    json.push_str("  ],\n");

    // ---------------- HMAC-SM3
    json.push_str("  \"hmac_sm3\": [\n");
    let hmac_cases: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
        (
            "key_basic",
            b"key".to_vec(),
            b"The quick brown fox jumps over the lazy dog".to_vec(),
        ),
        ("key_long", vec![0xab; 100], b"yanshu".to_vec()),
        ("msg_empty", b"k".to_vec(), Vec::new()),
    ];
    for (i, (name, key, msg)) in hmac_cases.iter().enumerate() {
        let tag = hmac_sm3(key, msg);
        json.push_str(&format!(
            "    {{\"name\": \"{}\", \"key\": {}, \"msg\": {}, \"tag\": {}}}{}\n",
            name,
            hex_vec(key),
            hex_vec(msg),
            hex_vec(&tag),
            if i + 1 == hmac_cases.len() { "" } else { "," }
        ));
    }
    json.push_str("  ],\n");

    // ---------------- HKDF-SM3
    json.push_str("  \"hkdf_sm3\": [\n");
    type HkdfCase = (&'static str, Vec<u8>, Vec<u8>, Vec<u8>, usize);
    let hkdf_cases: [HkdfCase; 4] = [
        (
            "basic_32",
            b"salt".to_vec(),
            b"ikm".to_vec(),
            b"info".to_vec(),
            32,
        ),
        (
            "block_key",
            layout::HKDF_SALT_BLOCK.to_vec(),
            vec![0x11; 32],
            vec![0x22; 16],
            16,
        ),
        ("long_64", Vec::new(), b"ikm".to_vec(), Vec::new(), 64),
        ("zero_len", b"s".to_vec(), b"i".to_vec(), b"n".to_vec(), 0),
    ];
    for (i, (name, salt, ikm, info, len)) in hkdf_cases.iter().enumerate() {
        let mut okm = vec![0u8; *len];
        hkdf_sm3(salt, ikm, info, &mut okm);
        json.push_str(&format!(
            "    {{\"name\": \"{}\", \"salt\": {}, \"ikm\": {}, \"info\": {}, \"len\": {}, \"okm\": {}}}{}\n",
            name,
            hex_vec(salt),
            hex_vec(ikm),
            hex_vec(info),
            len,
            hex_vec(&okm),
            if i + 1 == hkdf_cases.len() { "" } else { "," }
        ));
    }
    json.push_str("  ],\n");

    // ---------------- SM4-GCM
    json.push_str("  \"sm4_gcm\": [\n");
    struct GcmCase {
        name: &'static str,
        key: [u8; 16],
        nonce: Vec<u8>,
        aad: Vec<u8>,
        pt: Vec<u8>,
    }
    let gcm_cases = [
        GcmCase {
            name: "empty_plaintext",
            key: [0u8; 16],
            nonce: vec![0u8; 12],
            aad: Vec::new(),
            pt: Vec::new(),
        },
        GcmCase {
            name: "one_byte",
            key: {
                let mut k = [0u8; 16];
                for (i, b) in k.iter_mut().enumerate() {
                    *b = i as u8;
                }
                k
            },
            nonce: vec![0xAA; 12],
            aad: Vec::new(),
            pt: b"a".to_vec(),
        },
        GcmCase {
            name: "block_16",
            key: [0x01u8; 16],
            nonce: {
                let mut n = vec![0u8; 12];
                n[11] = 1;
                n
            },
            aad: Vec::new(),
            pt: (0..16).collect(),
        },
        GcmCase {
            name: "partial_15",
            key: {
                let mut k = [0u8; 16];
                for (i, b) in k.iter_mut().enumerate() {
                    *b = (0xF0 + i) as u8;
                }
                k
            },
            nonce: vec![0x5a; 12],
            aad: Vec::new(),
            pt: (0..15).collect(),
        },
        GcmCase {
            name: "aad_20_pt_1000",
            key: {
                let mut k = [0u8; 16];
                for (i, b) in k.iter_mut().enumerate() {
                    *b = (i * 3 + 1) as u8;
                }
                k
            },
            nonce: vec![0x11; 12],
            aad: (0..20).map(|i| (i * 5) as u8).collect(),
            pt: (0..1000).map(|i| (i * 13 + 7) as u8).collect(),
        },
        GcmCase {
            name: "pack_block_nonce_index5_last",
            key: [0x77u8; 16],
            nonce: layout::block_nonce(5, true).to_vec(),
            aad: vec![0x42; layout::HEADER_LEN],
            pt: (0..4096).map(|i| (i * 31 + 11) as u8).collect(),
        },
    ];
    for (i, c) in gcm_cases.iter().enumerate() {
        let mut ct = vec![0u8; c.pt.len()];
        let mut tag = [0u8; TAG_SIZE];
        gcm::encrypt(&c.key, &c.nonce, &c.aad, &c.pt, &mut ct, &mut tag);
        json.push_str(&format!(
            "    {{\"name\": \"{}\", \"key\": {}, \"nonce\": {}, \"aad\": {}, \"plaintext\": {}, \"ciphertext\": {}, \"tag\": {}}}{}\n",
            c.name,
            hex_vec(&c.key),
            hex_vec(&c.nonce),
            hex_vec(&c.aad),
            hex_vec(&c.pt),
            hex_vec(&ct),
            hex_vec(&tag),
            if i + 1 == gcm_cases.len() { "" } else { "," }
        ));
    }
    json.push_str("  ],\n");

    // ---------------- SM2
    let keys: Vec<(&str, [u8; 32], [u8; 64])> =
        ["yanshu-key-alice", "yanshu-key-bob", "yanshu-key-carol"]
            .iter()
            .map(|label| {
                let sk = private_key(label);
                let pk = sm2::public_from_private(&sk).expect("valid key");
                (*label, sk, pk)
            })
            .collect();

    json.push_str("  \"sm2\": {\n    \"keys\": [\n");
    for (i, (label, sk, pk)) in keys.iter().enumerate() {
        let za = sm2::z_a(pk, sm2::DEFAULT_ID);
        json.push_str(&format!(
            "      {{\"name\": \"{}\", \"priv\": {}, \"pub\": {}, \"za\": {}}}{}\n",
            label,
            hex_vec(sk),
            hex_vec(pk),
            hex_vec(&za),
            if i + 1 == keys.len() { "" } else { "," }
        ));
    }
    json.push_str("    ],\n    \"encrypt\": [\n");
    let encrypt_cases: Vec<(&str, usize, usize, &str)> = vec![
        ("dk_32", 0, 32, "k-enc-1"),
        ("one_byte", 0, 1, "k-enc-2"),
        ("max_255", 1, 255, "k-enc-3"),
        ("bob_32", 1, 32, "k-enc-4"),
    ];
    for (i, (name, key_idx, len, k_label)) in encrypt_cases.iter().enumerate() {
        let (_, sk, pk) = &keys[*key_idx];
        let msg: Vec<u8> = (0..*len).map(|j| (j * 17 + 29) as u8).collect();
        let k = scalar(k_label);
        let ct = sm2::encrypt(pk, &msg, &k).expect("encrypt");
        json.push_str(&format!(
            "      {{\"name\": \"{}\", \"priv\": {}, \"pub\": {}, \"k\": {}, \"plaintext\": {}, \"ciphertext\": {}}}{}\n",
            name,
            hex_vec(sk),
            hex_vec(pk),
            hex_vec(&k.to_be_bytes()),
            hex_vec(&msg),
            hex_vec(&ct),
            if i + 1 == encrypt_cases.len() { "" } else { "," }
        ));
    }
    json.push_str("    ],\n    \"sign\": [\n");
    let sign_cases: Vec<(&str, usize, &str, Vec<u8>)> = vec![
        ("msg_short", 0, "k-sig-1", b"yanshu manifest".to_vec()),
        ("msg_empty", 1, "k-sig-2", Vec::new()),
        ("msg_64", 2, "k-sig-3", (0..64).map(|i| i as u8).collect()),
    ];
    for (i, (name, key_idx, k_label, msg)) in sign_cases.iter().enumerate() {
        let (_, sk, pk) = &keys[*key_idx];
        let k = scalar(k_label);
        let sig = sm2::sign_with_k(sk, msg, sm2::DEFAULT_ID, &k)
            .expect("sign")
            .expect("k usable");
        json.push_str(&format!(
            "      {{\"name\": \"{}\", \"priv\": {}, \"pub\": {}, \"k\": {}, \"msg\": {}, \"sig\": {}}}{}\n",
            name,
            hex_vec(sk),
            hex_vec(pk),
            hex_vec(&k.to_be_bytes()),
            hex_vec(msg),
            hex_vec(&sig),
            if i + 1 == sign_cases.len() { "" } else { "," }
        ));
    }
    json.push_str("    ]\n  },\n");

    // ---------------- 用户码
    json.push_str("  \"user_codes\": [\n");
    for (i, (label, _sk, pk)) in keys.iter().enumerate() {
        let code = yanshu_sm::code::from_public_key(pk);
        // 规范化示例（大小写 / 混淆字符 / 分组）
        let lower = code.to_lowercase();
        let masked: String = lower
            .chars()
            .map(|c| match c {
                '0' => 'o',
                '1' => 'l',
                other => other,
            })
            .collect();
        let dotted = format!("{}-{}", &masked[..2], &masked[2..]);
        json.push_str(&format!(
            "    {{\"name\": \"{}\", \"pub\": {}, \"code\": \"{}\", \"normalize\": [{{\"in\": \"{}\", \"out\": \"{}\"}}, {{\"in\": \"{}\", \"out\": \"{}\"}}]}}{}\n",
            label,
            hex_vec(pk),
            code,
            masked,
            code,
            dotted,
            code,
            if i + 1 == keys.len() { "" } else { "," }
        ));
    }
    json.push_str("  ],\n");

    // ---------------- 加密包
    json.push_str("  \"pack\": [\n");
    struct PackCase {
        name: &'static str,
        data: Vec<u8>,
        block_size: u32,
        file_name: &'static str,
        mime: &'static str,
    }
    let pack_cases = [
        PackCase {
            name: "empty_file_one_block",
            data: Vec::new(),
            block_size: 16,
            file_name: "empty.txt",
            mime: "text/plain",
        },
        PackCase {
            name: "single_block_5",
            data: b"hello".to_vec(),
            block_size: 16,
            file_name: "hello.txt",
            mime: "text/plain",
        },
        PackCase {
            name: "four_blocks_64",
            data: (0..64).map(|i| (i * 11 + 3) as u8).collect(),
            block_size: 16,
            file_name: "报告.pdf",
            mime: "application/pdf",
        },
        PackCase {
            name: "partial_last_block_53",
            data: (0..53).map(|i| (i * 7 + 1) as u8).collect(),
            block_size: 16,
            file_name: "a.bin",
            mime: "application/octet-stream",
        },
    ];
    let alice = keys[0];
    let bob = keys[1];
    for (i, c) in pack_cases.iter().enumerate() {
        let dk = sm3(format!("dk-{}", c.name).as_bytes());
        let file_id_full = sm3(format!("file-id-{}", c.name).as_bytes());
        let mut file_id = [0u8; 16];
        file_id.copy_from_slice(&file_id_full[..16]);
        let params = PackParams {
            dk,
            file_id,
            k_wrap: scalar(&format!("k-wrap-{}", c.name)),
            k_sign: scalar(&format!("k-sign-{}", c.name)),
        };
        let input = PackInput {
            recipient_public: &bob.2,
            sender_private: &alice.1,
            name: c.file_name,
            mime: c.mime,
            block_size: c.block_size,
            data: &c.data,
        };
        let packed = pack::pack_with(&input, &params).expect("pack");
        // 自检：解包必须还原
        let out = pack::unpack(&packed, &bob.1, &alice.2).expect("unpack");
        assert_eq!(out.data, c.data);

        json.push_str(&format!(
            "    {{\"name\": \"{}\", \"recipient_priv\": {}, \"recipient_pub\": {}, \"sender_priv\": {}, \"sender_pub\": {}, \"dk\": {}, \"file_id\": {}, \"k_wrap\": {}, \"k_sign\": {}, \"block_size\": {}, \"file_name\": \"{}\", \"mime\": \"{}\", \"data\": {}, \"pack\": {}}}{}\n",
            c.name,
            hex_vec(&bob.1),
            hex_vec(&bob.2),
            hex_vec(&alice.1),
            hex_vec(&alice.2),
            hex_vec(&dk),
            hex_vec(&file_id),
            hex_vec(&params.k_wrap.to_be_bytes()),
            hex_vec(&params.k_sign.to_be_bytes()),
            c.block_size,
            c.file_name,
            c.mime,
            hex_vec(&c.data),
            hex_vec(&packed),
            if i + 1 == pack_cases.len() { "" } else { "," }
        ));
    }
    json.push_str("  ]\n}\n");

    if let Some(dir) = out_path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    fs::write(&out_path, json).expect("write vectors");
    eprintln!("wrote {}", out_path.display());
}
