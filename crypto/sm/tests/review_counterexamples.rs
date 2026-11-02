//! 评审要求的五类反例，逐条断言**具体错误名**（不许"尽力恢复"）。
//!
//! 1) 改 1 字节（块头 / 数据区）
//! 2) 删中间块
//! 3) 换两块顺序
//! 4) 搬入别的包里的合法块
//! 5) 截断
//!
//! 与 `section13_matrix.rs` 的 `check_01..22` 互补：那边按契约 §13 编号覆盖，
//! 这边按"评审给的五种攻击"覆盖，便于验收时直接对照。

use yanshu_sm::error::Error;
use yanshu_sm::pack::{self, PackInput};
use yanshu_sm::rng::SeedRng;
use yanshu_sm::sm2;

struct Fx {
    pack: Vec<u8>,
    recipient_priv: [u8; 32],
    chunk_off: usize,
    chunk_ends: Vec<usize>,
}

fn build(plain_len: usize, chunk_size: u32) -> Fx {
    build_with(b"review-fixture", plain_len, chunk_size)
}

fn build_with(tag: &[u8], plain_len: usize, chunk_size: u32) -> Fx {
    let mut rng = SeedRng::new(tag);
    let sender = sm2::keygen(&mut rng);
    let recipient = sm2::keygen(&mut rng);
    let mut recipient_pub = [0u8; 65];
    recipient_pub[0] = 0x04;
    recipient_pub[1..].copy_from_slice(&recipient.public_key);

    let plain: Vec<u8> = (0..plain_len).map(|i| (i * 19 + 5) as u8).collect();
    let input = PackInput {
        recipient_public: &recipient_pub,
        sender_private: &sender.private_key,
        name: "r.bin",
        mime: "application/octet-stream",
        ext: "bin",
        created_at_ms: 1_767_225_600_000,
        chunk_size,
        data: &plain,
    };
    let pack = pack::pack(&input, &mut rng).expect("pack");
    let header = pack::read_header(&pack).expect("header");
    let chunk_off = 112 + 65 + 129 + header.manifest_len as usize + header.sig_len as usize;
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
    Fx {
        pack,
        recipient_priv: recipient.private_key,
        chunk_off,
        chunk_ends,
    }
}

fn err(f: &Fx, p: &[u8]) -> Error {
    pack::unpack(p, &f.recipient_priv, None).unwrap_err()
}

/// 1a) 改块头里的 `PT_LEN`（1 字节级篡改，落在块头上）
#[test]
fn flip_one_byte_in_block_header() {
    let f = build(96, 32);
    let c0 = f.chunk_off;
    let mut p = f.pack.clone();
    p[c0 + 7] ^= 0x01; // PT_LEN 最低字节
    assert_eq!(err(&f, &p), Error::LengthInconsistent);
}

/// 1b) 改数据区 1 字节（密文）
#[test]
fn flip_one_byte_in_ciphertext() {
    let f = build(96, 32);
    let mut p = f.pack.clone();
    p[f.chunk_off + 16] ^= 0x01; // 第一块密文首字节
    assert_eq!(err(&f, &p), Error::ChunkAuthFailed);
}

/// 2) 删中间块（连同它的 16 字节块头与 tag 一起删）
#[test]
fn delete_middle_chunk() {
    let f = build(96, 32); // 3 块
    let c0 = f.chunk_off;
    let c1 = f.chunk_ends[0];
    let c2 = f.chunk_ends[1];
    let mut p = Vec::new();
    p.extend_from_slice(&f.pack[..c1]);
    p.extend_from_slice(&f.pack[c2..]);
    // 包长与 ENVELOPE_LEN 不符 → 长度层先拒绝（不会去"猜"缺了哪块）
    assert_eq!(err(&f, &p), Error::LengthInconsistent);
    // 若攻击者保留长度、只把中间块的块号改成 0/1，则命中块序层
    let mut q = f.pack.clone();
    q[c1..c1 + 4].copy_from_slice(&0u32.to_be_bytes());
    assert_eq!(err(&f, &q), Error::ChunkOrder);
    let _ = (c0, c2);
}

/// 3) 换两块顺序（0 与 1 对调）
#[test]
fn swap_two_chunks() {
    let f = build(96, 32);
    let c0 = f.chunk_off;
    let c1 = f.chunk_ends[0];
    let c2 = f.chunk_ends[1];
    let mut p = Vec::new();
    p.extend_from_slice(&f.pack[..c0]);
    p.extend_from_slice(&f.pack[c1..c2]);
    p.extend_from_slice(&f.pack[c0..c1]);
    p.extend_from_slice(&f.pack[c2..]);
    // 首条记录块号 1、期望 0 → 缺块（块序层，AAD 还没参与就已拒绝）
    assert_eq!(err(&f, &p), Error::ChunkMissing);
}

/// 4) 搬入**别的包**里的合法块（同发送方、同收件人、同样长度）
///
/// 攻击者把 B 包里的一条合法块记录（块号/长度都对）搬进 A 包：
/// 块号与 AAD 字段都"看起来合法"，但 AEAD 的 KEK 来自各自包的 DK，
/// 因此必然 `ChunkAuthFailed`——这正是 AAD 绑块序号+总块数+长度的价值。
#[test]
fn splice_chunk_from_another_pack() {
    let a = build(96, 32);
    let b = build_with(b"review-fixture-b", 96, 32); // 同结构、不同密钥/DK/KDF_SALT
    let c0 = a.chunk_off;
    let c1 = a.chunk_ends[0];

    let mut p = Vec::new();
    p.extend_from_slice(&a.pack[..c0]);
    // 注意：B 的签名 DER 长度可能与 A 不同，块偏移要按 B 自己的算
    p.extend_from_slice(&b.pack[b.chunk_off..b.chunk_ends[0]]); // 搬 B 的第 0 块
    p.extend_from_slice(&a.pack[c1..]);
    assert_eq!(err(&a, &p), Error::ChunkAuthFailed);
}

/// 5) 截断（尾部少几个字节 / 截到头部中间）
#[test]
fn truncate_pack() {
    let f = build(96, 32);
    for cut in [1usize, 40, 112, f.pack.len() - 20, f.pack.len() - 1] {
        assert_eq!(
            err(&f, &f.pack[..cut]),
            Error::LengthInconsistent,
            "cut = {}",
            cut
        );
    }
    // 头部都不完整时也不能 panic / 误判
    assert_eq!(err(&f, &[]), Error::LengthInconsistent);
}
