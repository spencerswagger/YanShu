//! 给服务端（Go/Core）的 SM2 验签供给包：`vectors/sm2-verify-vectors.json`
//!
//! ```text
//! cargo run --release --bin gen-core-vectors -- ../vectors
//! ```
//! 覆盖：正常签名 / 签名改 1 字节 / 消息被改 / userID 不同 / 公钥不符；
//! 以及 3 组 `SIG_INPUT` 逐字节样例（REGISTER / NICKNAME_UPDATE / TRANSFER_CREATE）。

use std::fs;
use std::path::PathBuf;

use yanshu_sm::bigint::U256;
use yanshu_sm::der;
use yanshu_sm::sm2;
use yanshu_sm::sm3::sm3;

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

fn arr32(hexs: &str) -> [u8; 32] {
    let v = unhex(hexs);
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

fn scalar(label: &str) -> U256 {
    let mut d = sm3(label.as_bytes());
    d[0] = 0;
    d[1] &= 0x7f;
    U256::from_be_bytes(&d)
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

fn sign_der(priv_hex: &str, msg: &[u8], id: &[u8], k: &str) -> Vec<u8> {
    let sk = arr32(priv_hex);
    let raw = sm2::sign_with_k(&sk, msg, id, &scalar(k))
        .expect("sign")
        .expect("k usable");
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&raw[..32]);
    s.copy_from_slice(&raw[32..]);
    der::encode_signature(&r, &s)
}

fn sig_input_register(code: &[u8; 4], pub65: &[u8; 65], nonce: &[u8; 32]) -> Vec<u8> {
    let mut v = b"YSAUTH1".to_vec();
    v.push(0x01);
    v.extend_from_slice(nonce);
    v.extend_from_slice(code);
    v.extend_from_slice(pub65);
    v
}

fn sig_input_nickname(code: &[u8; 4], nick: &[u8], nonce: &[u8; 32]) -> Vec<u8> {
    let mut v = b"YSAUTH1".to_vec();
    v.push(0x02);
    v.extend_from_slice(nonce);
    v.extend_from_slice(code);
    v.extend_from_slice(&(nick.len() as u16).to_be_bytes());
    v.extend_from_slice(nick);
    v
}

#[allow(clippy::too_many_arguments)]
fn sig_input_transfer(
    sender: &[u8; 4],
    recipient: &[u8; 4],
    size: u64,
    chunk_size: u32,
    chunk_count: u32,
    prelude_len: u32,
    prelude_sm3: &[u8; 32],
    nonce: &[u8; 32],
) -> Vec<u8> {
    let mut v = b"YSAUTH1".to_vec();
    v.push(0x03);
    v.extend_from_slice(nonce);
    v.extend_from_slice(sender);
    v.extend_from_slice(recipient);
    v.extend_from_slice(&size.to_be_bytes());
    v.extend_from_slice(&chunk_size.to_be_bytes());
    v.extend_from_slice(&chunk_count.to_be_bytes());
    v.extend_from_slice(&prelude_len.to_be_bytes());
    v.extend_from_slice(prelude_sm3);
    v
}

fn main() {
    let out_dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("../vectors"));
    let _ = fs::create_dir_all(&out_dir);

    // 固定夹具（与契约 §15.1 的发送方一致，便于和包签名对照）
    let d_hex = "00c1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f";
    let d = arr32(d_hex);
    let pk64 = sm2::public_from_private(&d).expect("pub");
    let pk65 = pub65(&pk64);
    let code = *b"AWQW";
    let nonce: [u8; 32] = core::array::from_fn(|i| i as u8);

    let id = sm2::DEFAULT_ID;
    let reg = sig_input_register(&code, &pk65, &nonce);
    let nick = sig_input_nickname(&code, "雁书用户".as_bytes(), &nonce);
    let prelude_sm3 = sm3(b"prelude-demo");
    let transfer = sig_input_transfer(b"AWQW", b"WTJF", 5, 1_048_576, 1, 485, &prelude_sm3, &nonce);

    let sig = sign_der(d_hex, &reg, id, "k-sig-core-1");
    let mut sig_flipped = sig.clone();
    sig_flipped[10] ^= 0x01;
    let mut msg_changed = reg.clone();
    msg_changed[20] ^= 0x01;

    // 另一把公钥（用来构造"公钥不符"）
    let other_d = priv_of("yanshu-core-other");
    let other_pk = pub65(&sm2::public_from_private(&other_d).expect("pub"));

    type Case = (
        &'static str,
        Vec<u8>,
        Vec<u8>,
        &'static [u8],
        [u8; 65],
        bool,
        &'static str,
    );
    let cases: Vec<Case> = vec![
        (
            "ok_register",
            reg.clone(),
            sig.clone(),
            id,
            pk65,
            true,
            "正常签名（REGISTER SIG_INPUT）",
        ),
        (
            "sig_flipped_1byte",
            reg.clone(),
            sig_flipped,
            id,
            pk65,
            false,
            "签名 DER 改 1 字节",
        ),
        (
            "msg_changed",
            msg_changed,
            sig.clone(),
            id,
            pk65,
            false,
            "消息改 1 字节（签名不变）",
        ),
        (
            "different_user_id",
            reg.clone(),
            sig.clone(),
            b"1234567812345679",
            pk65,
            false,
            "userID 不同（ZA 变）",
        ),
        (
            "wrong_public_key",
            reg.clone(),
            sig.clone(),
            id,
            other_pk,
            false,
            "公钥不符",
        ),
    ];

    let mut json = String::new();
    json.push_str("{\n");
    json.push_str("  \"meta\": {\n");
    json.push_str("    \"curve\": \"GB/T 32918 推荐曲线（sm2p256v1，a = p-3）\",\n");
    json.push_str("    \"user_id\": \"1234567812345678\",\n");
    json.push_str("    \"user_id_bits\": 128,\n");
    json.push_str("    \"za\": \"SM3(ENTL(2B, bit 数) ‖ ID ‖ a ‖ b ‖ Gx ‖ Gy ‖ Px ‖ Py)\",\n");
    json.push_str("    \"signed_digest\": \"e = SM3(ZA ‖ SIG_INPUT)\",\n");
    json.push_str("    \"signature_encoding\": \"DER SEQUENCE{r INTEGER, s INTEGER}，最短编码，70..72 字节\",\n");
    json.push_str("    \"pubkey_encoding\": \"65 字节 = 0x04 ‖ X(32) ‖ Y(32)，未压缩\",\n");
    json.push_str("    \"abi_note\": \"ys_sm2_verify_der 固定使用默认 userID；user_id 不同的用例只用于验证 ZA 口径，需在应用层用该 ID 复算\",\n");
    json.push_str("    \"sig_input_prefix\": \"YSAUTH1\",\n");
    json.push_str("    \"sig_input_layout\": \"YSAUTH1 ‖ PURPOSE(1) ‖ NONCE(32) ‖ 字段串；整数 u16be/u32be/u64be，字符串带长度前缀\"\n");
    json.push_str("  },\n");

    json.push_str("  \"sig_input_samples\": [\n");
    let samples: Vec<(&str, &str, Vec<u8>, &str)> = vec![
        (
            "REGISTER",
            "01",
            reg.clone(),
            "CODE(4) 紧接 NONCE(32) 之后；然后 PUBKEY(65)",
        ),
        (
            "NICKNAME_UPDATE",
            "02",
            nick.clone(),
            "CODE(4) 之后是 u16be(NICK_LEN) + NICKNAME(UTF-8)",
        ),
        (
            "TRANSFER_CREATE",
            "03",
            transfer.clone(),
            "SENDER_CODE(4)‖RECIPIENT_CODE(4)‖u64 size‖u32 chunk_size‖u32 chunk_count‖u32 prelude_len‖PRELUDE_SM3(32)",
        ),
    ];
    for (i, (purpose, pb, bytes, note)) in samples.iter().enumerate() {
        json.push_str(&format!(
            "    {{\"purpose\": \"{}\", \"purpose_byte\": \"{}\", \"len\": {}, \"sig_input\": \"{}\", \"note\": \"{}\"}}{}\n",
            purpose,
            pb,
            bytes.len(),
            hex(bytes),
            note,
            if i + 1 == samples.len() { "" } else { "," }
        ));
    }
    json.push_str("  ],\n");

    json.push_str("  \"verify_vectors\": [\n");
    for (i, (name, msg, sig_der, vid, vpub, expect, _note)) in cases.iter().enumerate() {
        // 自检：用 Rust 实现验一遍，并且派生中间量供 Core 自查
        let za = sm2::z_a(&vpub[1..].try_into().expect("64"), vid);
        let e = sm2::message_digest(&vpub[1..].try_into().expect("64"), msg, vid);
        let ok = {
            let (r, s) = der::decode_signature(sig_der).expect("der");
            let mut raw = [0u8; 64];
            raw[..32].copy_from_slice(&r);
            raw[32..].copy_from_slice(&s);
            sm2::verify(&vpub[1..].try_into().expect("64"), msg, vid, &raw).expect("verify")
        };
        assert_eq!(ok, *expect, "vector {} 自检失败", name);

        json.push_str(&format!(
            "    {{\"name\": \"{}\", \"pub65\": \"{}\", \"user_id\": \"{}\", \"msg\": \"{}\", \"za\": \"{}\", \"digest_e\": \"{}\", \"sig_der\": \"{}\", \"sig_der_len\": {}, \"expect_verify\": {}}}{}\n",
            name,
            hex(vpub),
            String::from_utf8_lossy(vid),
            hex(msg),
            hex(&za),
            hex(&e),
            hex(sig_der),
            sig_der.len(),
            expect,
            if i + 1 == cases.len() { "" } else { "," }
        ));
    }
    json.push_str("  ],\n");

    // 私钥单独放一段（Core 构造自己的用例用；也便于核对公钥派生）
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
        "wrote {} ({} SIG_INPUT samples, {} verify vectors)",
        path.display(),
        samples.len(),
        cases.len()
    );
}
