//! 给服务端（Go/Core）的 SM2 验签供给包：`vectors/sm2-verify-vectors.json`
//!
//! ```text
//! cargo run --release --bin gen-core-vectors -- ../vectors
//! ```
//!
//! 覆盖：
//! * 七种 `PURPOSE` 各一条正例（REGISTER / NICKNAME_UPDATE / TRANSFER_CREATE /
//!   TRANSFER_REVOKE / INBOX_LIST / WS_HELLO / TRANSFER_ACK）；
//! * 负例：消息改 1 字节、签名改 1 字节、换公钥、长度前缀写错、`CODE` 与请求头不一致、
//!   空输入、超长输入、userID 不同。
//!
//! 每条给逐字段构造（`sig_input_fields`）、最终 `sig_input`、`za`、`digest_e`、`sig_der`
//! 与两种期望：`expect_verify`（密码学层面）与 `expect_server`（服务端策略层面）。

use std::fs;
use std::path::PathBuf;

use yanshu_sm::bigint::U256;
use yanshu_sm::der;
use yanshu_sm::sm2;
use yanshu_sm::sm3::sm3;

const ID: &[u8] = b"1234567812345678";
const PREFIX: &[u8] = b"YSAUTH1";
const TRANSFER_ID: &str = "0123456789abcdef0123456789abcdef"; // 32 ASCII

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

fn priv_of(label: &str) -> [u8; 32] {
    let mut d = sm3(label.as_bytes());
    d[0] = 0;
    d[1] &= 0x7f;
    d
}

fn scalar(label: &str) -> U256 {
    U256::from_be_bytes(&priv_of(label))
}

fn pub65(pub64: &[u8; 64]) -> [u8; 65] {
    let mut p = [0u8; 65];
    p[0] = 0x04;
    p[1..].copy_from_slice(pub64);
    p
}

fn sign_der(priv_bytes: &[u8; 32], msg: &[u8], id: &[u8], k: &str) -> Vec<u8> {
    let raw = sm2::sign_with_k(priv_bytes, msg, id, &scalar(k))
        .expect("sign")
        .expect("k usable");
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&raw[..32]);
    s.copy_from_slice(&raw[32..]);
    der::encode_signature(&r, &s)
}

fn verify_raw(pub65_bytes: &[u8; 65], msg: &[u8], id: &[u8], sig_der: &[u8]) -> bool {
    let (r, s) = match der::decode_signature(sig_der) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let mut raw = [0u8; 64];
    raw[..32].copy_from_slice(&r);
    raw[32..].copy_from_slice(&s);
    let pub64: [u8; 64] = pub65_bytes[1..].try_into().expect("64");
    sm2::verify(&pub64, msg, id, &raw).unwrap_or(false)
}

/// 逐字段拼 `SIG_INPUT`，返回（字段列表，完整字节）
type Field = (&'static str, Vec<u8>);
fn build(fields: Vec<Field>) -> (Vec<Field>, Vec<u8>) {
    let mut out = Vec::new();
    for (_, b) in &fields {
        out.extend_from_slice(b);
    }
    (fields, out)
}

fn sig_input_register(pub65_bytes: &[u8; 65], code: &[u8; 4], nonce: &[u8; 32]) -> Vec<Field> {
    vec![
        ("SIGN_PREFIX", PREFIX.to_vec()),
        ("PURPOSE", vec![0x01]),
        ("NONCE", nonce.to_vec()),
        ("CODE", code.to_vec()),
        ("PUBKEY", pub65_bytes.to_vec()),
    ]
}

fn main() {
    let out_dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("../vectors"));
    let _ = fs::create_dir_all(&out_dir);

    let d = priv_of("yanshu-core-signer");
    let d_hex = hex(&d);
    let pk64 = sm2::public_from_private(&d).expect("pub");
    let pk65 = pub65(&pk64);
    let other_d = priv_of("yanshu-core-other");
    let other_pk = pub65(&sm2::public_from_private(&other_d).expect("pub"));
    let code = *b"AWQW";
    let recipient = *b"WTJF";
    let nonce: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
    let prelude_sm3 = sm3(b"prelude-demo");
    let tid = TRANSFER_ID.as_bytes();

    // ---- 七种 PURPOSE 的字段串
    let p1 = sig_input_register(&pk65, &code, &nonce);
    let nick = "雁书用户".as_bytes();
    let p2 = vec![
        ("SIGN_PREFIX", PREFIX.to_vec()),
        ("PURPOSE", vec![0x02]),
        ("NONCE", nonce.to_vec()),
        ("CODE", code.to_vec()),
        (
            "NICK_LEN(u16be)",
            (nick.len() as u16).to_be_bytes().to_vec(),
        ),
        ("NICKNAME", nick.to_vec()),
    ];
    let p3 = vec![
        ("SIGN_PREFIX", PREFIX.to_vec()),
        ("PURPOSE", vec![0x03]),
        ("NONCE", nonce.to_vec()),
        ("SENDER_CODE", code.to_vec()),
        ("RECIPIENT_CODE", recipient.to_vec()),
        ("PLAINTEXT_SIZE(u64be)", 5u64.to_be_bytes().to_vec()),
        ("CHUNK_SIZE(u32be)", 1_048_576u32.to_be_bytes().to_vec()),
        ("CHUNK_COUNT(u32be)", 1u32.to_be_bytes().to_vec()),
        ("PRELUDE_LEN(u32be)", 485u32.to_be_bytes().to_vec()),
        ("PRELUDE_SM3", prelude_sm3.to_vec()),
    ];
    let p4 = vec![
        ("SIGN_PREFIX", PREFIX.to_vec()),
        ("PURPOSE", vec![0x04]),
        ("NONCE", nonce.to_vec()),
        ("SENDER_CODE", code.to_vec()),
        ("TRANSFER_ID(32 ASCII)", tid.to_vec()),
    ];
    let p5 = vec![
        ("SIGN_PREFIX", PREFIX.to_vec()),
        ("PURPOSE", vec![0x05]),
        ("NONCE", nonce.to_vec()),
        ("CODE", code.to_vec()),
    ];
    let p6 = vec![
        ("SIGN_PREFIX", PREFIX.to_vec()),
        ("PURPOSE", vec![0x06]),
        ("NONCE", nonce.to_vec()),
        ("CODE", code.to_vec()),
    ];
    let p7 = vec![
        ("SIGN_PREFIX", PREFIX.to_vec()),
        ("PURPOSE", vec![0x07]),
        ("NONCE", nonce.to_vec()),
        ("RECEIVER_CODE", recipient.to_vec()),
        ("TRANSFER_ID(32 ASCII)", tid.to_vec()),
    ];

    type Field = (&'static str, Vec<u8>);
    type Purpose = (&'static str, Vec<Field>);
    let purposes: Vec<Purpose> = vec![
        ("REGISTER", p1.clone()),
        ("NICKNAME_UPDATE", p2.clone()),
        ("TRANSFER_CREATE", p3.clone()),
        ("TRANSFER_REVOKE", p4.clone()),
        ("INBOX_LIST", p5.clone()),
        ("WS_HELLO", p6.clone()),
        ("TRANSFER_ACK", p7.clone()),
    ];

    // ---- 生成向量：正例 7 条 + 负例
    struct Vec_ {
        name: &'static str,
        purpose: &'static str,
        fields: Option<Vec<Field>>,
        msg: Vec<u8>,
        pub65: [u8; 65],
        id: Vec<u8>,
        sig: Vec<u8>,
        expect_verify: bool,
        expect_server: &'static str,
        code_in_sig: &'static str,
        request_code: &'static str,
        note: &'static str,
    }

    let mut vectors: Vec<Vec_> = Vec::new();
    for (purpose, fields) in &purposes {
        let msg: Vec<u8> = fields.iter().flat_map(|(_, b)| b.iter().copied()).collect();
        let sig = sign_der(&d, &msg, ID, &format!("k-{}", purpose));
        vectors.push(Vec_ {
            name: purpose,
            purpose,
            fields: Some(fields.clone()),
            msg,
            pub65: pk65,
            id: ID.to_vec(),
            sig,
            expect_verify: true,
            expect_server: "OK",
            code_in_sig: "AWQW",
            request_code: "AWQW",
            note: "正例",
        });
    }

    // 负例 1：消息改 1 字节
    let mut msg_changed = p1
        .iter()
        .flat_map(|(_, b)| b.iter().copied())
        .collect::<Vec<u8>>();
    msg_changed[PREFIX.len() + 1 + 32 + 1] ^= 0x01; // CODE 里改一位
    let sig_p1 = sign_der(
        &d,
        &p1.iter()
            .flat_map(|(_, b)| b.iter().copied())
            .collect::<Vec<u8>>(),
        ID,
        "k-REGISTER",
    );
    vectors.push(Vec_ {
        name: "msg_changed",
        purpose: "REGISTER",
        fields: None,
        msg: msg_changed,
        pub65: pk65,
        id: ID.to_vec(),
        sig: sig_p1.clone(),
        expect_verify: false,
        expect_server: "CRYPTO_SIGNATURE_INVALID",
        code_in_sig: "AWQW",
        request_code: "AWQW",
        note: "SIG_INPUT 改 1 字节（CODE 位），签名不变",
    });

    // 负例 2：签名改 1 字节
    let mut sig_flipped = sig_p1.clone();
    sig_flipped[10] ^= 0x01;
    vectors.push(Vec_ {
        name: "sig_flipped_1byte",
        purpose: "REGISTER",
        fields: None,
        msg: p1.iter().flat_map(|(_, b)| b.iter().copied()).collect(),
        pub65: pk65,
        id: ID.to_vec(),
        sig: sig_flipped,
        expect_verify: false,
        expect_server: "CRYPTO_SIGNATURE_INVALID",
        code_in_sig: "AWQW",
        request_code: "AWQW",
        note: "DER 里 r 的第 3 字节取反",
    });

    // 负例 3：换公钥
    vectors.push(Vec_ {
        name: "wrong_public_key",
        purpose: "REGISTER",
        fields: None,
        msg: p1.iter().flat_map(|(_, b)| b.iter().copied()).collect(),
        pub65: other_pk,
        id: ID.to_vec(),
        sig: sig_p1.clone(),
        expect_verify: false,
        expect_server: "CRYPTO_SIGNATURE_INVALID",
        code_in_sig: "AWQW",
        request_code: "AWQW",
        note: "公钥换成另一把（ZA 与验签都变）",
    });

    // 负例 4：长度前缀写错（昵称 12 字节，前缀写成 11）
    let mut bad_prefix = p2
        .iter()
        .flat_map(|(_, b)| b.iter().copied())
        .collect::<Vec<u8>>();
    let len_off = PREFIX.len() + 1 + 32 + 4;
    bad_prefix[len_off..len_off + 2].copy_from_slice(&11u16.to_be_bytes());
    let sig_p2 = sign_der(
        &d,
        &p2.iter()
            .flat_map(|(_, b)| b.iter().copied())
            .collect::<Vec<u8>>(),
        ID,
        "k-NICKNAME_UPDATE",
    );
    vectors.push(Vec_ {
        name: "bad_length_prefix",
        purpose: "NICKNAME_UPDATE",
        fields: None,
        msg: bad_prefix,
        pub65: pk65,
        id: ID.to_vec(),
        sig: sig_p2,
        expect_verify: false,
        expect_server: "CRYPTO_SIGNATURE_INVALID",
        code_in_sig: "AWQW",
        request_code: "AWQW",
        note: "昵称 12 字节但 u16be 前缀写成 11 → 拼出的字节与签名时不同",
    });

    // 负例 5：CODE 与请求头不一致（签名本身有效，服务端比对失败）
    vectors.push(Vec_ {
        name: "code_mismatch",
        purpose: "REGISTER",
        fields: None,
        msg: p1.iter().flat_map(|(_, b)| b.iter().copied()).collect(),
        pub65: pk65,
        id: ID.to_vec(),
        sig: sig_p1.clone(),
        expect_verify: true,
        expect_server: "AUTH_CODE_MISMATCH",
        code_in_sig: "AWQW",
        request_code: "ZZZZ",
        note: "验签通过，但 X-YS-Code=ZZZZ ≠ SIG_INPUT 里的 CODE(AWQW)",
    });

    // 负例 6：空输入（密码学可验，但协议不允许）
    let empty_sig = sign_der(&d, b"", ID, "k-empty");
    vectors.push(Vec_ {
        name: "empty_message",
        purpose: "NONE",
        fields: None,
        msg: Vec::new(),
        pub65: pk65,
        id: ID.to_vec(),
        sig: empty_sig,
        expect_verify: true,
        expect_server: "BAD_INPUT",
        code_in_sig: "",
        request_code: "AWQW",
        note: "空消息的签名能验过，但 SIG_INPUT 至少含前缀+用途+nonce，服务端应按 BAD_INPUT 拒",
    });

    // 负例 7：超长输入（4096 字节，密码学可验，协议不允许）
    let long_msg: Vec<u8> = (0..4096).map(|i| (i * 13 + 7) as u8).collect();
    let long_sig = sign_der(&d, &long_msg, ID, "k-long");
    vectors.push(Vec_ {
        name: "oversized_input",
        purpose: "NONE",
        fields: None,
        msg: long_msg,
        pub65: pk65,
        id: ID.to_vec(),
        sig: long_sig,
        expect_verify: true,
        expect_server: "BAD_INPUT",
        code_in_sig: "",
        request_code: "AWQW",
        note:
            "4096 字节消息，契约所有 PURPOSE 的 SIG_INPUT 都是定长小消息，服务端应按 BAD_INPUT 拒",
    });

    // 负例 8：userID 不同（只用于 ZA 口径；ABI 固定默认 ID）
    vectors.push(Vec_ {
        name: "different_user_id",
        purpose: "REGISTER",
        fields: None,
        msg: p1.iter().flat_map(|(_, b)| b.iter().copied()).collect(),
        pub65: pk65,
        id: b"1234567812345679".to_vec(),
        sig: sig_p1,
        expect_verify: false,
        expect_server: "CRYPTO_SIGNATURE_INVALID",
        code_in_sig: "AWQW",
        request_code: "AWQW",
        note: "换 userID 后 ZA 变，验签必须失败",
    });

    // ---- 自检 + 输出
    let mut json = String::new();
    json.push_str("{\n");
    json.push_str("  \"meta\": {\n");
    json.push_str("    \"curve\": \"GB/T 32918 推荐曲线（sm2p256v1，a = p-3）\",\n");
    json.push_str("    \"user_id\": \"1234567812345678\",\n");
    json.push_str("    \"entl\": \"0x0080（128 bit）\",\n");
    json.push_str("    \"za\": \"SM3(ENTL(2B, bit 数) ‖ ID ‖ a(32) ‖ b(32) ‖ Gx(32) ‖ Gy(32) ‖ Px(32) ‖ Py(32))\",\n");
    json.push_str("    \"signed_digest\": \"e = SM3(ZA ‖ SIG_INPUT)；SIG_INPUT 是下面给出的原始字节，不要在调用方先算 SM3\",\n");
    json.push_str("    \"signature_encoding\": \"DER SEQUENCE{r INTEGER, s INTEGER}，最短编码，70..72 字节\",\n");
    json.push_str("    \"pubkey_encoding\": \"65 字节 = 0x04 ‖ X(32) ‖ Y(32)\",\n");
    json.push_str("    \"sig_input_formula\": \"YSAUTH1(7) ‖ PURPOSE(1) ‖ NONCE(32) ‖ <该用途字段串>；整数一律大端：u16be/u32be/u64be；字符串带显式长度前缀\",\n");
    json.push_str("    \"abi_note\": \"ys_sm2_verify_der 固定默认 userID；different_user_id 用例需在应用层用该 ID 复算 ZA\",\n");
    json.push_str("    \"expect_verify\": \"密码学层面：签名与 pub/消息/userID 是否匹配\",\n");
    json.push_str("    \"expect_server\": \"服务端策略层面：OK / AUTH_CODE_MISMATCH / CRYPTO_SIGNATURE_INVALID / BAD_INPUT\"\n");
    json.push_str("  },\n");

    json.push_str("  \"sig_input_samples\": [\n");
    for (i, (purpose, fields)) in purposes.iter().enumerate() {
        let (_, msg) = build(fields.clone());
        let flist: Vec<String> = fields
            .iter()
            .map(|(n, b)| {
                format!(
                    "{{\"field\": \"{}\", \"len\": {}, \"hex\": \"{}\"}}",
                    n,
                    b.len(),
                    hex(b)
                )
            })
            .collect();
        json.push_str(&format!(
            "    {{\"purpose\": \"{}\", \"len\": {}, \"sig_input\": \"{}\", \"fields\": [{}]}}{}\n",
            purpose,
            msg.len(),
            hex(&msg),
            flist.join(", "),
            if i + 1 == purposes.len() { "" } else { "," }
        ));
    }
    json.push_str("  ],\n");

    json.push_str("  \"verify_vectors\": [\n");
    for (i, v) in vectors.iter().enumerate() {
        let pub64: [u8; 64] = v.pub65[1..].try_into().expect("64");
        let za = sm2::z_a(&pub64, &v.id);
        let e = sm2::message_digest(&pub64, &v.msg, &v.id);
        let got = verify_raw(&v.pub65, &v.msg, &v.id, &v.sig);
        assert_eq!(got, v.expect_verify, "vector {} 自检失败", v.name);

        let fields_json = match &v.fields {
            Some(fs) => {
                let items: Vec<String> = fs
                    .iter()
                    .map(|(n, b)| {
                        format!(
                            "{{\"field\": \"{}\", \"len\": {}, \"hex\": \"{}\"}}",
                            n,
                            b.len(),
                            hex(b)
                        )
                    })
                    .collect();
                format!("[{}]", items.join(", "))
            }
            None => "null".to_string(),
        };

        json.push_str(&format!(
            "    {{\"name\": \"{}\", \"purpose\": \"{}\", \"pub65\": \"{}\", \"user_id\": \"{}\", \"code_in_sig\": \"{}\", \"request_code\": \"{}\", \"sig_input\": \"{}\", \"sig_input_len\": {}, \"sig_input_fields\": {}, \"za\": \"{}\", \"digest_e\": \"{}\", \"sig_der\": \"{}\", \"sig_der_len\": {}, \"expect_verify\": {}, \"expect_server\": \"{}\", \"note\": \"{}\"}}{}\n",
            v.name,
            v.purpose,
            hex(&v.pub65),
            String::from_utf8_lossy(&v.id),
            v.code_in_sig,
            v.request_code,
            hex(&v.msg),
            v.msg.len(),
            fields_json,
            hex(&za),
            hex(&e),
            hex(&v.sig),
            v.sig.len(),
            v.expect_verify,
            v.expect_server,
            v.note,
            if i + 1 == vectors.len() { "" } else { "," }
        ));
    }
    json.push_str("  ],\n");

    json.push_str(&format!(
        "  \"fixtures\": {{\"priv\": \"{}\", \"pub65\": \"{}\", \"other_priv\": \"{}\", \"other_pub65\": \"{}\"}}\n",
        d_hex,
        hex(&pk65),
        hex(&other_d),
        hex(&other_pk)
    ));
    json.push_str("}\n");

    let path = out_dir.join("sm2-verify-vectors.json");
    fs::write(&path, json).expect("write vectors");
    eprintln!(
        "wrote {} ({} SIG_INPUT samples, {} verify vectors: {} positive / {} negative)",
        path.display(),
        purposes.len(),
        vectors.len(),
        vectors.iter().filter(|v| v.expect_verify).count(),
        vectors.iter().filter(|v| !v.expect_verify).count()
    );
}
