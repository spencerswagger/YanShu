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

/// 算法参数口径（宿主侧用 GmSSL/其它实现复算时必须按这个口径）。
const CONVENTIONS: &str = r#"  "conventions": {
    "sm3": {
      "standard": "GB/T 32905-2016",
      "digest_bytes": 32,
      "input": "msg 字段原样作为字节流（空串表示 0 字节）"
    },
    "hmac_sm3": {
      "standard": "RFC 2104 结构，PRF = SM3",
      "block_size": 64,
      "key_handling": "key 长度 > 64 时先 SM3(key) 再左补零到 64；否则直接左补零到 64",
      "output_bytes": 32
    },
    "hkdf_sm3": {
      "standard": "RFC 5869 结构，PRF = HMAC-SM3，HashLen = 32",
      "salt_empty": "salt 为空时用 32 字节 0x00",
      "info": "info 字段原样拼接",
      "max_output": "255*32 字节",
      "out_len": "len 字段（0 表示空输出）"
    },
    "sm4_gcm": {
      "standard": "GB/T 36624-2018 / SP 800-38D 构造，分组密码 = SM4",
      "key_bytes": 16,
      "key_bits": 128,
      "tag_bytes": 16,
      "tag_bits": 128,
      "nonce_bytes": "见每条向量的 nonce_len；本套件固定 12（96 位）",
      "iv_construction": "nonce 长度 12 时 J0 = nonce || 00 00 00 01；否则 J0 = GHASH(H, {}, nonce)",
      "aad": "aad 字段原样作为附加认证数据，可为空",
      "ciphertext": "与 plaintext 等长（GCM 不填充、不改变长度）",
      "tag_position": "向量里 ciphertext 与 tag 分开存；命令行/库若输出 ct||tag 连写，tag 是末尾 16 字节",
      "ghash": "GF(2^128) 位反射约定（MSB 对应 x^0）"
    },
    "sm2": {
      "standard": "GB/T 32918（推荐曲线 sm2p256v1，a = p-3）",
      "private_key": "32 字节大端标量 d ∈ [1, n-2]",
      "public_key": "64 字节 = X(32) || Y(32)，**未压缩点、不带 0x04 前缀**",
      "ciphertext_order": "C1C3C2 平文拼接：C1.x(32) || C1.y(32) || C3(32) || C2(len)",
      "c1_point_encoding": "同上，C1 只放 X||Y 两个坐标，不带 0x04、不做 DER 包装",
      "signature_format": "**raw R||S**，R(32) || S(32)，不是 DER SEQUENCE",
      "user_id": "1234567812345678（ENTL = 0x0080）",
      "za": "ZA = SM3(ENTL || ID || a || b || Gx || Gy || Px || Py)",
      "signature_digest": "e = SM3(ZA || M)，签名值对 e 计算",
      "k": "每条向量显式给出临时标量 k（< n）；宿主侧用 GmSSL 复算时需固定 rand_bytes 或直接调底层",
      "kdf": "SM2 KDF：ct 从 1 递增，SM3(x2||y2||ct_be32) 拼接后截断；全零则重试",
      "plaintext_len_range": "1..=255（GmSSL 的 SM2_MAX_PLAINTEXT_SIZE）"
    },
    "user_code": {
      "alphabet": "0123456789ABCDEFGHJKMNPQRSTVWXYZ（去掉 I L O U）",
      "derive": "对公钥 64 字节做 SM3，取摘要前 20 bit（大端位序、每 5 bit 一个符号）编成 4 位码",
      "normalization": "转大写；O→0；I/L→1；去掉 '-'（以及空白）；U 非法；长度必须正好 4",
      "check_symbol": "未并入用户码（保持 4 位）；code::check_symbol 仅为可选工具"
    },
    "pack": {
      "version": 1,
      "header_len": 40,
      "header_fields": "magic(4)=YSPK | version(1)=1 | suite(1)=1 | flags(1)=bit0=1 | reserved(1)=0 | file_id(16) | block_size(4) | block_count(4) | plain_size(8)",
      "record_order": "HEADER | KEY_REC | SIG_REC | MANIFEST_REC | BLOCK(0..n-1)",
      "key_rec": "kind(1)=1 | len(4)=128 | SM2(C1C3C2) 封装的 32 字节 DK",
      "sig_rec": "kind(1)=2 | len(4)=64 | SM2 签名 R||S，签名对象 = HEADER || MANIFEST_PLAINTEXT",
      "manifest_rec": "ct_len(4) | ct | tag(16)",
      "manifest_nonce": "ffffffffffffffff 80 000000（12 字节）",
      "block_nonce": "index_be32 || 00000000 || flag(1) || 000000，flag=1 仅末块",
      "block_rec": "index(4) | flags(1) | ct_len(4) | ct | tag(16)",
      "kdf_block": "HKDF-SM3(salt=\"YanShu/v1/block\", ikm=DK, info=file_id, 16B)",
      "kdf_manifest": "HKDF-SM3(salt=\"YanShu/v1/manifest\", ikm=DK, info=file_id, 16B)",
      "aad": "HEADER 40 字节（每个数据块与清单都用它做 AAD）",
      "block_digest": "SM3(ct || tag)，写进清单",
      "block_count": "max(1, ceil(plain_size / block_size))；空文件 = 1 个空块",
      "manifest_plaintext": "u16 name_len | name | u16 mime_len | mime | u32 block_size | u32 block_count | u64 plain_size | u32 digest_count | 32*digest_count"
    }
  },
"#;

fn packed_block_count(plain_size: usize, block_size: u32) -> usize {
    if plain_size == 0 {
        1
    } else {
        plain_size.div_ceil(block_size as usize)
    }
}

fn main() {
    let out_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("../testdata/vectors.json"));

    let mut json = String::new();
    json.push_str("{\n");
    json.push_str("  \"meta\": {\"suite\": \"SM4-GCM-128/SM3/SM2-C1C3C2\", \"pack_version\": 1, \"id\": \"1234567812345678\", \"generated_by\": \"yanshu-sm gen-vectors\", \"byte_order\": \"所有整数与 hex 字段均为大端/网络序；hex 为小写，无 0x 前缀\"},\n");
    json.push_str(CONVENTIONS);

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
            "    {{\"name\": \"{}\", \"key\": {}, \"key_bits\": 128, \"nonce\": {}, \"nonce_len\": {}, \"aad\": {}, \"aad_len\": {}, \"plaintext\": {}, \"plaintext_len\": {}, \"ciphertext\": {}, \"tag\": {}}}{}\n",
            c.name,
            hex_vec(&c.key),
            hex_vec(&c.nonce),
            c.nonce.len(),
            hex_vec(&c.aad),
            c.aad.len(),
            hex_vec(&c.pt),
            c.pt.len(),
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
            "      {{\"name\": \"{}\", \"priv\": {}, \"pub\": {}, \"k\": {}, \"plaintext\": {}, \"plaintext_len\": {}, \"ciphertext\": {}, \"ciphertext_len\": {}}}{}\n",
            name,
            hex_vec(sk),
            hex_vec(pk),
            hex_vec(&k.to_be_bytes()),
            hex_vec(&msg),
            msg.len(),
            hex_vec(&ct),
            ct.len(),
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
            "      {{\"name\": \"{}\", \"priv\": {}, \"pub\": {}, \"k\": {}, \"msg\": {}, \"msg_len\": {}, \"sig\": {}, \"sig_len\": 64}}{}\n",
            name,
            hex_vec(sk),
            hex_vec(pk),
            hex_vec(&k.to_be_bytes()),
            hex_vec(msg),
            msg.len(),
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
            "    {{\"name\": \"{}\", \"recipient_priv\": {}, \"recipient_pub\": {}, \"sender_priv\": {}, \"sender_pub\": {}, \"dk\": {}, \"file_id\": {}, \"k_wrap\": {}, \"k_sign\": {}, \"block_size\": {}, \"file_name\": \"{}\", \"mime\": \"{}\", \"data\": {}, \"plaintext_len\": {}, \"block_count\": {}, \"pack\": {}, \"pack_bytes\": {}}}{}\n",
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
            c.data.len(),
            packed_block_count(c.data.len(), c.block_size),
            hex_vec(&packed),
            packed.len(),
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
