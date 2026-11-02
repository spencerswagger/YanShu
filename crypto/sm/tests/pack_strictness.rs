//! `YSPK/1.0` 严格性矩阵：每种篡改都要落到**契约 §13 的具体错误码**。

use yanshu_sm::bigint::U256;
use yanshu_sm::error::Error;
use yanshu_sm::pack::{self, PackInput, PackParams};
use yanshu_sm::rng::{Rng, SeedRng};
use yanshu_sm::sm2;

const HDR: usize = 112;
const PUB: usize = 65;
const WRAP: usize = 129;

struct Fixture {
    pack: Vec<u8>,
    recipient_priv: [u8; 32],
    sender_pub: [u8; 65],
    sender_code: String,
    manifest_off: usize,
    sig_off: usize,
    chunk_off: usize,
    chunk_ends: Vec<usize>,
    plain: Vec<u8>,
}

fn build(plain_len: usize, chunk_size: u32) -> Fixture {
    let mut rng = SeedRng::new(b"strictness-fixture");
    let sender = sm2::keygen(&mut rng);
    let recipient = sm2::keygen(&mut rng);
    let mut recipient_pub = [0u8; 65];
    recipient_pub[0] = 0x04;
    recipient_pub[1..].copy_from_slice(&recipient.public_key);
    let mut sender_pub = [0u8; 65];
    sender_pub[0] = 0x04;
    sender_pub[1..].copy_from_slice(&sender.public_key);

    let plain: Vec<u8> = (0..plain_len).map(|i| (i * 37 + 11) as u8).collect();
    let mut dk = [0u8; 32];
    rng.fill(&mut dk);
    let mut salt = [0u8; 16];
    rng.fill(&mut salt);
    let params = PackParams {
        dk,
        kdf_salt: salt,
        k_enc: U256::from_be_bytes(&{
            let mut b = [0u8; 32];
            rng.fill(&mut b);
            b
        }),
        k_sig: U256::from_be_bytes(&{
            let mut b = [0u8; 32];
            rng.fill(&mut b);
            b
        }),
    };
    let input = PackInput {
        recipient_public: &recipient_pub,
        sender_private: &sender.private_key,
        name: "f.bin",
        mime: "application/octet-stream",
        ext: "bin",
        created_at_ms: 1_767_225_600_000,
        chunk_size,
        data: &plain,
    };
    let pack = pack::pack_with_params(&input, &params).expect("pack");
    let header = pack::read_header(&pack).expect("header");
    let manifest_off = HDR + PUB + WRAP;
    let sig_off = manifest_off + header.manifest_len as usize;
    let chunk_off = sig_off + header.sig_len as usize;
    let mut chunk_ends = Vec::new();
    let mut pos = chunk_off;
    for i in 0..header.chunk_count {
        let pt_len = pack::chunk_plain_len(
            header.plaintext_size,
            header.chunk_size,
            header.chunk_count,
            i,
        ) as usize;
        pos += 16 + pt_len + 16;
        chunk_ends.push(pos);
    }
    assert_eq!(pos, pack.len());

    let code = {
        let mut p = [0u8; 65];
        p[0] = 0x04;
        p[1..].copy_from_slice(&sender.public_key);
        yanshu_sm::code::from_public_key(&p)
    };

    Fixture {
        pack,
        recipient_priv: recipient.private_key,
        sender_pub,
        sender_code: code,
        manifest_off,
        sig_off,
        chunk_off,
        chunk_ends,
        plain,
    }
}

fn err(f: &Fixture, p: &[u8]) -> Error {
    pack::unpack(p, &f.recipient_priv, None).unwrap_err()
}

#[test]
fn header_checks_map_to_contract_errors() {
    let f = build(64, 32);

    let mut p = f.pack.clone();
    p[0] ^= 0x01;
    assert_eq!(err(&f, &p), Error::BadMagic);

    let mut p = f.pack.clone();
    p[4] = 2;
    assert_eq!(err(&f, &p), Error::UnsupportedVersion);

    let mut p = f.pack.clone();
    p[5] = 1;
    assert_eq!(err(&f, &p), Error::UnsupportedVersion);

    let mut p = f.pack.clone();
    p[6..8].copy_from_slice(&111u16.to_be_bytes());
    assert_eq!(err(&f, &p), Error::HeaderInvalid);

    let mut p = f.pack.clone();
    p[12] = 9;
    assert_eq!(err(&f, &p), Error::AlgUnsupported);

    // FLAGS 保留位
    let mut p = f.pack.clone();
    p[11] |= 0x04;
    assert_eq!(err(&f, &p), Error::BadFlags);

    // SENDER_SIGNED = 0
    let mut p = f.pack.clone();
    p[11] &= !0x02;
    assert_eq!(err(&f, &p), Error::Unsigned);

    // RESERVED 非零
    let mut p = f.pack.clone();
    p[100] = 1;
    assert_eq!(err(&f, &p), Error::HeaderInvalid);

    // CHUNK_SIZE 越界
    let mut p = f.pack.clone();
    p[16..20].copy_from_slice(&8u32.to_be_bytes());
    assert_eq!(err(&f, &p), Error::HeaderInvalid);

    // CHUNK_COUNT 与 PLAINTEXT_SIZE 不自洽
    let mut p = f.pack.clone();
    p[20..24].copy_from_slice(&5u32.to_be_bytes());
    assert_eq!(err(&f, &p), Error::LengthInconsistent);

    // WRAPPED_KEY_LEN
    let mut p = f.pack.clone();
    p[32..40].copy_from_slice(&128u64.to_be_bytes());
    assert_eq!(err(&f, &p), Error::LengthInconsistent);

    // SIG_LEN 越界
    let mut p = f.pack.clone();
    p[72..80].copy_from_slice(&10u64.to_be_bytes());
    assert_eq!(err(&f, &p), Error::HeaderInvalid);
}

#[test]
fn truncation_and_trailing_are_rejected() {
    let f = build(64, 32);
    // 截掉尾部
    for cut in [1usize, 10, HDR, HDR + PUB + WRAP, f.pack.len() - 1] {
        assert!(pack::unpack(&f.pack[..cut], &f.recipient_priv, None).is_err());
    }
    // 尾部多字节 → 尾随字节（与截断、字段矛盾分开）
    let mut p = f.pack.clone();
    p.push(0);
    assert_eq!(err(&f, &p), Error::TrailingBytes);
}

#[test]
fn crypto_sections_map_to_errors() {
    let f = build(64, 32);

    // 清单密文改 1 字节 → 清单认证失败
    let mut p = f.pack.clone();
    p[f.manifest_off] ^= 0x01;
    assert_eq!(err(&f, &p), Error::ManifestAuthFailed);

    // 签名段首字节（DER 的 0x30）被改 → 先命中 SIG_LEN 与 DER 自述长度校验（§13 #11）
    let mut p = f.pack.clone();
    p[f.sig_off] ^= 0x01;
    assert_eq!(err(&f, &p), Error::HeaderInvalid);

    // 改 DER 里的 r/s（结构仍合法）→ 验签失败
    let mut p = f.pack.clone();
    p[f.sig_off + 10] ^= 0x01;
    assert_eq!(err(&f, &p), Error::SignatureMismatch);

    // 块密文改 1 字节 → 块认证失败（tag 覆盖）
    let mut p = f.pack.clone();
    p[f.chunk_off + 20] ^= 0x01;
    assert_eq!(err(&f, &p), Error::ChunkAuthFailed);

    // 换收件人私钥 → 解封失败
    let mut rng = SeedRng::new(b"other-recipient");
    let other = sm2::keygen(&mut rng);
    assert_eq!(
        pack::unpack(&f.pack, &other.private_key, None).unwrap_err(),
        Error::BadKeyRecord
    );

    // SENDER_PUB 换掉 → 签名失败或曲线错误（C1 与签名都绑了公钥）
    let mut p = f.pack.clone();
    p[HDR + 10] ^= 0x01;
    assert!(pack::unpack(&p, &f.recipient_priv, None).is_err());

    // 期望码不匹配 → CRYPTO_SENDER_MISMATCH
    assert_eq!(
        pack::unpack(&f.pack, &f.recipient_priv, Some("ZZZZ")).unwrap_err(),
        Error::SenderMismatch
    );
}

#[test]
fn chunk_order_missing_duplicate() {
    let f = build(96, 32); // 3 块
    assert_eq!(f.chunk_ends.len(), 3);
    let c0 = f.chunk_off;
    let c1 = f.chunk_ends[0];
    let c2 = f.chunk_ends[1];

    // 交换块 0 与块 1 → 首条记录 index=1 而期望 0 → 缺块
    let mut p = Vec::new();
    p.extend_from_slice(&f.pack[..c0]);
    p.extend_from_slice(&f.pack[c1..c2]);
    p.extend_from_slice(&f.pack[c0..c1]);
    p.extend_from_slice(&f.pack[c2..]);
    assert_eq!(err(&f, &p), Error::ChunkMissing);

    // 用块 0 覆盖块 1（块号 0,0,2）→ 重复块 / 顺序错
    let mut p = Vec::new();
    p.extend_from_slice(&f.pack[..c0]);
    p.extend_from_slice(&f.pack[c0..c1]);
    p.extend_from_slice(&f.pack[c0..c1]);
    p.extend_from_slice(&f.pack[c2..]);
    assert_eq!(err(&f, &p), Error::ChunkOrder);

    // 直接删掉块 1 的字节 → 包长不足，命中 CRYPTO_TRUNCATED
    let mut p = Vec::new();
    p.extend_from_slice(&f.pack[..c1]);
    p.extend_from_slice(&f.pack[c2..]);
    assert_eq!(err(&f, &p), Error::Truncated);

    // 末块标志被改
    let last = f.chunk_off;
    let _ = last;
    let mut p = f.pack.clone();
    let last_rec = f.chunk_ends[1];
    p[last_rec + 12] = 0; // 块 2 是末块，LAST_FLAG 应为 1
    assert_eq!(err(&f, &p), Error::ChunkOrder);

    // 块头 PT_LEN 篡改
    let mut p = f.pack.clone();
    p[c0 + 4..c0 + 8].copy_from_slice(&16u32.to_be_bytes());
    assert_eq!(err(&f, &p), Error::LengthInconsistent);

    // 正常包可解
    let out = pack::unpack(&f.pack, &f.recipient_priv, Some(&f.sender_code)).expect("ok");
    assert_eq!(out.data, f.plain);
    let _ = f.sender_pub;
}

#[test]
fn every_byte_flip_is_rejected_or_covered() {
    let f = build(40, 16);
    for pos in 0..f.pack.len() {
        let mut p = f.pack.clone();
        p[pos] ^= 0x01;
        assert!(
            pack::unpack(&p, &f.recipient_priv, None).is_err(),
            "byte {} flipped but unpacked",
            pos
        );
    }
}
