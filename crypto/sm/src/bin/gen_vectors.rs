//! 生成测试向量（全 hex JSON，契约 `YSPK/1.0` 口径）。
//!
//! ```text
//! cargo run --release --bin gen-vectors -- ../testdata/vectors.json
//! ```
//!
//! 所有向量都是**确定性**的：密钥、临时标量 k、DK、KDF_SALT、created_at 全部钉死，
//! 因此宿主侧可以用 OpenSSL/GmSSL 逐字节复算（口径见文件里的 `conventions`）。

use std::fs;
use std::path::PathBuf;

use yanshu_sm::bigint::U256;
use yanshu_sm::der;
use yanshu_sm::gcm::{self, TAG_SIZE};
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

fn hex_vec(b: &[u8]) -> String {
    format!("\"{}\"", hex(b))
}

/// 由标签派生一个 < n 的标量（清最高字节，保证小于曲线阶）。
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

fn pub65(pub64: &[u8; 64]) -> [u8; 65] {
    let mut p = [0u8; 65];
    p[0] = 0x04;
    p[1..].copy_from_slice(pub64);
    p
}

const CONVENTIONS: &str = r#"  "conventions": {
    "pack_version": "YSPK/1.0",
    "byte_order": "所有整数与 hex 均为大端/网络序；hex 小写、无 0x 前缀",
    "sm3": { "standard": "GB/T 32905-2016", "digest_bytes": 32 },
    "sm2": {
      "user_id": "1234567812345678",
      "entl": "0x0080（大端 00 80）",
      "za": "SM3(ENTL ‖ ID ‖ a ‖ b ‖ Gx ‖ Gy ‖ Px ‖ Py)，P 为签名者公钥",
      "signed_digest": "e = SM3(ZA ‖ msg)；msg 传原文，不要预哈希"
    },
    "hmac_sm3": {
      "standard": "RFC 2104，PRF = SM3",
      "block_size": 64,
      "key_handling": "key > 64 字节时先 SM3(key) 再左补零到 64；否则直接左补零",
      "output_bytes": 32
    },
    "hkdf_sm3": {
      "standard": "RFC 5869，PRF = HMAC-SM3，HashLen = 32",
      "salt_empty": "32 字节 0x00",
      "max_output": "255*32 字节"
    },
    "sm4_gcm": {
      "standard": "GB/T 36624-2018 / SP 800-38D，分组密码 = SM4",
      "key_bytes": 16, "tag_bytes": 16, "nonce_bytes": 12,
      "iv_construction": "nonce 长度 12 → J0 = nonce || 00 00 00 01",
      "ciphertext": "与明文等长",
      "ghash": "GF(2^128) 位反射（MSB 对应 x^0）",
      "tag_position": "向量里 ciphertext 与 tag 分开；gmssl 命令行输出为 ct||tag"
    },
    "sm2": {
      "standard": "GB/T 32918 推荐曲线（a = p-3）",
      "private_key": "32 字节大端标量 d ∈ [1, n-2]",
      "public_key_primitive": "64 字节 = X||Y，**不带 0x04**（向量里字段名 pub）",
      "public_key_contract": "65 字节 = 0x04||X||Y（向量里字段名 pub65，包内用这个）",
      "ciphertext_primitive": "64+32+len：C1.x||C1.y||C3||C2，**不带 0x04**",
      "ciphertext_contract": "129 字节 = 0x04||C1.x||C1.y||C3||C2（包内 WRAPPED_KEY 用这个）",
      "signature_primitive": "raw R||S（64 字节）",
      "signature_contract": "DER SEQUENCE{r,s}（70..72 字节）",
      "user_id": "1234567812345678（ENTL = 0x0080）",
      "za": "SM3(ENTL || ID || a || b || Gx || Gy || Px || Py)"
    },
    "user_code": {
      "pub_input": "未压缩 65 字节公钥（含 0x04）",
      "derive": "SM3(PUB65) 前 20 bit（大端位序、5 bit/符号）→ Crockford Base32 4 位",
      "check_symbol": "20 bit 当 u32 V，CHECK_ALPHA[V mod 37]；展示为 CODE-CHECK，不占那 4 位",
      "normalization": "大写 → 去 '-'/空白 → O→0、I/L→1 → 必须正好 4 位且都在字母表内（U 非法）"
    },
    "pack": {
      "contract": "docs/CRYPTO-PACK.md v1（YSPK/1.0）",
      "header_len": 112,
      "segments": "HEADER(112) | SENDER_PUB(65,0x04) | WRAPPED_KEY(129,0x04) | MANIFEST_SEC | SIG_SEC | CHUNK_SEC",
      "chunk_nonce": "u64be(index) || 00 00 00 || last_flag",
      "manifest_nonce": "ffffffffffffffff 00000001",
      "aad_chunk": "31 字节见契约 §7.2（label=01|magic|ver|chunk_size|chunk_count|plaintext_size|index|last|pt_len）",
      "aad_manifest": "31 字节见契约 §7.3（label=02|magic|ver|flags|chunk_size|chunk_count|plaintext_size|manifest_pt_len）",
      "kdf": "HKDF-SM3(ikm=DK, salt=KDF_SALT, info=\"YANSHU/v1/chunk-key\"/\"YANSHU/v1/manifest-key\", 16B)",
      "chunk_digest": "SM3(明文块)，进清单",
      "sig_input": "\"YSSIG1\"||0100||HEADER[0..72)||SENDER_PUB(65)||MANIFEST_SEC",
      "chunk_record": "index(4)|pt_len(4)|ct_len(4)|last(1)|reserved(1+2)|ct|tag(16)"
    }
  },
"#;

fn main() {
    let out_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("../testdata/vectors.json"));

    let mut json = String::new();
    json.push_str("{\n");
    json.push_str("  \"meta\": {\"suite\": \"SM4-GCM-128/SM3/SM2-C1C3C2\", \"pack_version\": \"YSPK/1.0\", \"id\": \"1234567812345678\", \"generated_by\": \"yanshu-sm gen-vectors\"},\n");
    json.push_str(CONVENTIONS);

    // ---------------- SM3
    json.push_str("  \"sm3\": [\n");
    let big: Vec<u8> = (0..(1024 * 1024)).map(|i| (i * 31 + 7) as u8).collect();
    let cases: Vec<(&str, Vec<u8>, bool)> = vec![
        ("empty", Vec::new(), true),
        ("one_byte_00", vec![0x00], true),
        ("abc", b"abc".to_vec(), true),
        (
            "utf8_chinese",
            "雁书：一次可信的传输".as_bytes().to_vec(),
            true,
        ),
        (
            "abcd_x16",
            b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd".to_vec(),
            true,
        ),
        ("one_mib", big, false), // 太大，只给摘要 + 生成规则
    ];
    for (i, (name, msg, inline)) in cases.iter().enumerate() {
        let digest = sm3(msg);
        if *inline {
            json.push_str(&format!(
                "    {{\"name\": \"{}\", \"msg\": {}, \"msg_len\": {}, \"digest\": {}}}{}\n",
                name,
                hex_vec(msg),
                msg.len(),
                hex_vec(&digest),
                if i + 1 == cases.len() { "" } else { "," }
            ));
        } else {
            json.push_str(&format!(
                "    {{\"name\": \"{}\", \"msg\": null, \"msg_len\": {}, \"msg_rule\": \"byte[i] = (i*31 + 7) & 0xff, i = 0..{}\", \"digest\": {}}}{}\n",
                name,
                msg.len(),
                msg.len(),
                hex_vec(&digest),
                if i + 1 == cases.len() { "" } else { "," }
            ));
        }
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

    // ---------------- HKDF-SM3（契约 §11 参数）
    json.push_str("  \"hkdf_sm3\": [\n");
    type HkdfCase = (&'static str, Vec<u8>, Vec<u8>, Vec<u8>, usize);
    let hkdf_cases: [HkdfCase; 4] = [
        (
            "contract_chunk_key",
            b"000102030405060708090a0b0c0d0e0f".to_vec(),
            Vec::new(),
            v1::KDF_INFO_CHUNK.to_vec(),
            16,
        ),
        (
            "contract_manifest_key",
            b"000102030405060708090a0b0c0d0e0f".to_vec(),
            Vec::new(),
            v1::KDF_INFO_MANIFEST.to_vec(),
            16,
        ),
        (
            "basic_64",
            b"salt".to_vec(),
            b"ikm".to_vec(),
            b"info".to_vec(),
            64,
        ),
        (
            "empty_output",
            b"s".to_vec(),
            b"i".to_vec(),
            b"n".to_vec(),
            0,
        ),
    ];
    let dk_contract = sm3(b"yanshu-dk-fixture");
    for (i, (name, salt, ikm, info, len)) in hkdf_cases.iter().enumerate() {
        // 前两条用契约夹具的 DK；后两条用普通输入
        let ikm_bytes: Vec<u8> = if name.starts_with("contract_") {
            dk_contract.to_vec()
        } else {
            ikm.clone()
        };
        let mut okm = vec![0u8; *len];
        hkdf_sm3(salt, &ikm_bytes, info, &mut okm);
        json.push_str(&format!(
            "    {{\"name\": \"{}\", \"salt\": {}, \"ikm\": {}, \"info\": {}, \"len\": {}, \"okm\": {}}}{}\n",
            name,
            hex_vec(salt),
            hex_vec(&ikm_bytes),
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
    let header_aad = {
        // 用契约 §15.2 的 AAD_CHUNK 作为"真实 AAD"样例
        vec![
            0x01, 0x59, 0x53, 0x50, 0x4b, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x05,
        ]
    };
    let gcm_cases: [GcmCase; 6] = [
        GcmCase {
            name: "empty_plaintext",
            key: [0u8; 16],
            nonce: vec![0u8; 12],
            aad: Vec::new(),
            pt: Vec::new(),
        },
        GcmCase {
            name: "one_byte",
            key: [0x01u8; 16],
            nonce: vec![0xAA; 12],
            aad: Vec::new(),
            pt: b"a".to_vec(),
        },
        GcmCase {
            name: "exact_block_16",
            key: [0x02u8; 16],
            nonce: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1].to_vec(),
            aad: Vec::new(),
            pt: (0..16).collect(),
        },
        GcmCase {
            name: "partial_15",
            key: [0x03u8; 16],
            nonce: vec![0x5a; 12],
            aad: Vec::new(),
            pt: (0..15).collect(),
        },
        GcmCase {
            name: "aad_20_pt_1000",
            key: [0x04u8; 16],
            nonce: vec![0x11; 12],
            aad: (0..20).map(|i| (i * 5) as u8).collect(),
            pt: (0..1000).map(|i| (i * 13 + 7) as u8).collect(),
        },
        GcmCase {
            name: "contract_chunk0",
            key: [0x05u8; 16],
            nonce: v1::chunk_nonce(0, true).to_vec(),
            aad: header_aad,
            pt: b"hello".to_vec(),
        },
    ];
    for (i, c) in gcm_cases.iter().enumerate() {
        let mut ct = vec![0u8; c.pt.len()];
        let mut tag = [0u8; TAG_SIZE];
        gcm::encrypt(&c.key, &c.nonce, &c.aad, &c.pt, &mut ct, &mut tag);
        json.push_str(&format!(
            "    {{\"name\": \"{}\", \"key\": {}, \"key_bits\": 128, \"nonce\": {}, \"nonce_len\": {}, \"aad\": {}, \"aad_len\": {}, \"plaintext\": {}, \"plaintext_len\": {}, \"ciphertext\": {}, \"tag\": {}}}{}\n",
            c.name, hex_vec(&c.key), hex_vec(&c.nonce), c.nonce.len(), hex_vec(&c.aad), c.aad.len(),
            hex_vec(&c.pt), c.pt.len(), hex_vec(&ct), hex_vec(&tag),
            if i + 1 == gcm_cases.len() { "" } else { "," }
        ));
    }
    json.push_str("  ],\n");

    // ---------------- SM2
    type KeyRow = (&'static str, [u8; 32], [u8; 64], [u8; 65]);
    let keys: Vec<KeyRow> = ["yanshu-key-alice", "yanshu-key-bob", "yanshu-key-carol"]
        .iter()
        .map(|label| {
            let sk = private_key(label);
            let pk = sm2::public_from_private(&sk).expect("valid key");
            (*label, sk, pk, pub65(&pk))
        })
        .collect();

    json.push_str("  \"sm2\": {\n    \"keys\": [\n");
    for (i, (label, sk, pk, p65)) in keys.iter().enumerate() {
        let za = sm2::z_a(pk, sm2::DEFAULT_ID);
        json.push_str(&format!(
            "      {{\"name\": \"{}\", \"priv\": {}, \"pub\": {}, \"pub65\": {}, \"za\": {}}}{}\n",
            label,
            hex_vec(sk),
            hex_vec(pk),
            hex_vec(p65),
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
        let (_, sk, pk, _) = &keys[*key_idx];
        let msg: Vec<u8> = (0..*len).map(|j| (j * 17 + 29) as u8).collect();
        let k = scalar(k_label);
        let ct = sm2::encrypt(pk, &msg, &k).expect("encrypt");
        json.push_str(&format!(
            "      {{\"name\": \"{}\", \"priv\": {}, \"pub\": {}, \"k\": {}, \"plaintext\": {}, \"plaintext_len\": {}, \"ciphertext\": {}, \"ciphertext_len\": {}}}{}\n",
            name, hex_vec(sk), hex_vec(pk), hex_vec(&k.to_be_bytes()), hex_vec(&msg), msg.len(),
            hex_vec(&ct), ct.len(),
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
        let (_, sk, pk, _) = &keys[*key_idx];
        let k = scalar(k_label);
        let raw = sm2::sign_with_k(sk, msg, sm2::DEFAULT_ID, &k)
            .expect("sign")
            .expect("k usable");
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&raw[..32]);
        s.copy_from_slice(&raw[32..]);
        let der = der::encode_signature(&r, &s);
        json.push_str(&format!(
            "      {{\"name\": \"{}\", \"priv\": {}, \"pub\": {}, \"k\": {}, \"msg\": {}, \"msg_len\": {}, \"sig_raw\": {}, \"sig_der\": {}, \"sig_der_len\": {}}}{}\n",
            name, hex_vec(sk), hex_vec(pk), hex_vec(&k.to_be_bytes()), hex_vec(msg), msg.len(),
            hex_vec(&raw), hex_vec(&der), der.len(),
            if i + 1 == sign_cases.len() { "" } else { "," }
        ));
    }
    json.push_str("    ]\n  },\n");

    // ---------------- 用户码
    json.push_str("  \"user_codes\": [\n");
    for (i, (label, _sk, _pk, p65)) in keys.iter().enumerate() {
        let code = yanshu_sm::code::from_public_key(p65);
        let check = yanshu_sm::code::check_symbol(p65);
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
            "    {{\"name\": \"{}\", \"pub65\": {}, \"code\": \"{}\", \"check\": \"{}\", \"normalize\": [{{\"in\": \"{}\", \"out\": \"{}\"}}, {{\"in\": \"{}\", \"out\": \"{}\"}}]}}{}\n",
            label, hex_vec(p65), code, check, masked, code, dotted, code,
            if i + 1 == keys.len() { "" } else { "," }
        ));
    }
    json.push_str("  ],\n");

    // ---------------- 加密包
    json.push_str("  \"pack\": [\n");
    let alice = keys[0];
    let bob = keys[1];

    // 契约 §15 夹具
    let fixture_dk: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let fixture_salt: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let fixture_k_enc = U256::from_be_bytes(&{
        let mut b = [0u8; 32];
        b.copy_from_slice(&sm2_hex(
            "59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21",
        ));
        b
    });
    let fixture_k_sig = U256::from_be_bytes(&{
        let mut b = [0u8; 32];
        b.copy_from_slice(&sm2_hex(
            "6cb28d99385c175c94f94e934817663fc176d925dd72b727260dbaae1fb2f96f",
        ));
        b
    });
    let fixture_recipient = pub65_from_hex(
        "0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13",
    );
    let fixture_sender_priv =
        sm2_hex("00c1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f");
    let mut fixture_sender_priv32 = [0u8; 32];
    fixture_sender_priv32.copy_from_slice(&fixture_sender_priv);

    struct PackCase {
        name: &'static str,
        data: Vec<u8>,
        chunk_size: u32,
        file_name: &'static str,
        mime: &'static str,
        ext: &'static str,
        sender_label: &'static str,
        recipient_label: &'static str,
        // true = 用契约 §15 夹具（§15.1）而不是 yanshu-key-*
        contract_fixture: bool,
    }
    let pack_cases: Vec<PackCase> = vec![
        PackCase {
            name: "contract_v1_minimal",
            data: b"hello".to_vec(),
            chunk_size: 1_048_576,
            file_name: "hi.txt",
            mime: "text/plain",
            ext: "txt",
            sender_label: "contract",
            recipient_label: "contract",
            contract_fixture: true,
        },
        PackCase {
            name: "contract_v2_multi_chunk",
            data: (0u8..0x50).collect(),
            chunk_size: 32,
            file_name: "multi.bin",
            mime: "application/octet-stream",
            ext: "bin",
            sender_label: "contract",
            recipient_label: "contract",
            contract_fixture: true,
        },
        PackCase {
            name: "empty_file",
            data: Vec::new(),
            chunk_size: 16,
            file_name: "empty.bin",
            mime: "application/octet-stream",
            ext: "bin",
            sender_label: "alice",
            recipient_label: "bob",
            contract_fixture: false,
        },
        PackCase {
            name: "three_chunks_odd_tail",
            data: (0..70).map(|i| (i * 11 + 3) as u8).collect(),
            chunk_size: 32,
            file_name: "报告.bin",
            mime: "application/octet-stream",
            ext: "bin",
            sender_label: "alice",
            recipient_label: "bob",
            contract_fixture: false,
        },
    ];

    for (i, c) in pack_cases.iter().enumerate() {
        let (recipient_pub, recipient_priv, sender_priv, sender_pub) = if c.contract_fixture {
            let sp = sm2::public_from_private(&fixture_sender_priv32).expect("pub");
            (
                fixture_recipient,
                fixture_recipient_priv(),
                fixture_sender_priv32,
                pub65(&sp),
            )
        } else {
            let s = keys
                .iter()
                .find(|k| k.0.ends_with(c.sender_label))
                .expect("sender");
            let r = keys
                .iter()
                .find(|k| k.0.ends_with(c.recipient_label))
                .expect("recipient");
            (r.3, r.1, s.1, s.3)
        };

        let params = if c.contract_fixture {
            PackParams {
                dk: fixture_dk,
                kdf_salt: fixture_salt,
                k_enc: fixture_k_enc,
                k_sig: fixture_k_sig,
            }
        } else {
            PackParams {
                dk: sm3(c.name.as_bytes()),
                kdf_salt: {
                    let mut s = [0u8; 16];
                    s.copy_from_slice(&sm3(format!("salt-{}", c.name).as_bytes())[..16]);
                    s
                },
                k_enc: scalar(&format!("k-enc-{}", c.name)),
                k_sig: scalar(&format!("k-sig-{}", c.name)),
            }
        };

        let input = PackInput {
            recipient_public: &recipient_pub,
            sender_private: &sender_priv,
            name: c.file_name,
            mime: c.mime,
            ext: c.ext,
            created_at_ms: 1_767_225_600_000,
            chunk_size: c.chunk_size,
            data: &c.data,
        };
        let packed = pack::pack_with_params(&input, &params).expect("pack");
        // 自检：解包必须还原
        let out = pack::unpack(&packed, &recipient_priv, None).expect("unpack");
        assert_eq!(out.data, c.data);

        json.push_str(&format!(
            "    {{\"name\": \"{}\", \"recipient_pub\": {}, \"sender_priv\": {}, \"sender_pub\": {}, \"recipient_priv\": {}, \"dk\": {}, \"kdf_salt\": {}, \"k_enc\": {}, \"k_sig\": {}, \"created_at_ms\": 1767225600000, \"chunk_size\": {}, \"file_name\": \"{}\", \"mime\": \"{}\", \"ext\": \"{}\", \"data\": {}, \"plaintext_len\": {}, \"chunk_count\": {}, \"pack\": {}, \"pack_bytes\": {}}}{}\n",
            c.name,
            hex_vec(&recipient_pub),
            hex_vec(&sender_priv),
            hex_vec(&sender_pub),
            hex_vec(&recipient_priv),
            hex_vec(&params.dk),
            hex_vec(&params.kdf_salt),
            hex_vec(&params.k_enc.to_be_bytes()),
            hex_vec(&params.k_sig.to_be_bytes()),
            c.chunk_size,
            c.file_name,
            c.mime,
            c.ext,
            hex_vec(&c.data),
            c.data.len(),
            packed_chunk_count(c.data.len(), c.chunk_size),
            hex_vec(&packed),
            packed.len(),
            if i + 1 == pack_cases.len() { "" } else { "," }
        ));
        let _ = (alice, bob);
    }
    json.push_str("  ]\n}\n");

    if let Some(dir) = out_path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    fs::write(&out_path, json).expect("write vectors");
    eprintln!("wrote {}", out_path.display());
}

/// 契约 §15.1 的接收方私钥（测试夹具）
fn fixture_recipient_priv() -> [u8; 32] {
    let mut b = [0u8; 32];
    b.copy_from_slice(&sm2_hex(
        "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8",
    ));
    b
}

fn sm2_hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

fn pub65_from_hex(s: &str) -> [u8; 65] {
    let v = sm2_hex(s);
    let mut out = [0u8; 65];
    out.copy_from_slice(&v);
    out
}

fn packed_chunk_count(plain_size: usize, chunk_size: u32) -> usize {
    if plain_size == 0 {
        1
    } else {
        plain_size.div_ceil(chunk_size as usize)
    }
}
