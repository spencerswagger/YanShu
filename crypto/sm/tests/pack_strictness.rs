//! 加密包严格性矩阵：每一种篡改都必须落到**具体错误码**（不是笼统的"失败"）。

use yanshu_sm::error::Error;
use yanshu_sm::pack::{self, layout, PackInput};
use yanshu_sm::rng::SeedRng;
use yanshu_sm::sm2;

struct Fixture {
    pack: Vec<u8>,
    recipient_priv: [u8; 32],
    sender_pub: [u8; 64],
    /// 第 i 个块在包内的字节范围
    blocks: Vec<(usize, usize)>,
}

fn build(data: &[u8], block_size: u32) -> Fixture {
    let mut rng = SeedRng::new(b"strictness-fixture");
    let alice = sm2::keygen(&mut rng);
    let bob = sm2::keygen(&mut rng);
    let input = PackInput {
        recipient_public: &bob.public_key,
        sender_private: &alice.private_key,
        name: "f.bin",
        mime: "application/octet-stream",
        block_size,
        data,
    };
    let pack = pack::pack(&input, &mut rng).expect("pack");

    // 定位块边界
    let mut pos = layout::HEADER_LEN;
    pos += 1 + 4 + 128; // KEY_REC
    pos += 1 + 4 + 64; // SIG_REC
    let man_len = u32::from_be_bytes(pack[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4 + man_len + layout::TAG_LEN;
    let mut blocks = Vec::new();
    while pos < pack.len() {
        let ct_len = u32::from_be_bytes(pack[pos + 5..pos + 9].try_into().unwrap()) as usize;
        let end = pos + 9 + ct_len + layout::TAG_LEN;
        blocks.push((pos, end));
        pos = end;
    }
    assert_eq!(pos, pack.len());

    Fixture {
        pack,
        recipient_priv: bob.private_key,
        sender_pub: alice.public_key,
        blocks,
    }
}

fn err(f: &Fixture, pack: &[u8]) -> Error {
    pack::unpack(pack, &f.recipient_priv, &f.sender_pub).unwrap_err()
}

fn ok(f: &Fixture, pack: &[u8], expect: &[u8]) {
    let out = pack::unpack(pack, &f.recipient_priv, &f.sender_pub).expect("unpack ok");
    assert_eq!(out.data, expect);
}

#[test]
fn header_mutations_map_to_specific_errors() {
    let data: Vec<u8> = (0..64).map(|i| i as u8).collect();
    let f = build(&data, 16);

    let mut p = f.pack.clone();
    p[0] ^= 0x01;
    assert_eq!(err(&f, &p), Error::BadMagic);

    let mut p = f.pack.clone();
    p[layout::OFF_VERSION] = 2;
    assert_eq!(err(&f, &p), Error::UnsupportedVersion);

    let mut p = f.pack.clone();
    p[layout::OFF_SUITE] = 9;
    assert_eq!(err(&f, &p), Error::UnsupportedVersion);

    let mut p = f.pack.clone();
    p[layout::OFF_FLAGS] = 0;
    assert_eq!(err(&f, &p), Error::BadFlags);

    let mut p = f.pack.clone();
    p[layout::OFF_RESERVED] = 1;
    assert_eq!(err(&f, &p), Error::BadFlags);

    let mut p = f.pack.clone();
    p[layout::OFF_BLOCK_SIZE..layout::OFF_BLOCK_SIZE + 4].copy_from_slice(&0u32.to_be_bytes());
    assert_eq!(err(&f, &p), Error::BadFlags);

    // 块数与 plain_size 不自洽
    let mut p = f.pack.clone();
    p[layout::OFF_BLOCK_COUNT..layout::OFF_BLOCK_COUNT + 4].copy_from_slice(&3u32.to_be_bytes());
    assert_eq!(err(&f, &p), Error::ManifestMismatch);

    // 改 plain_size（与 block_count / 清单不自洽）
    let mut p = f.pack.clone();
    p[layout::OFF_PLAIN_SIZE..layout::OFF_PLAIN_SIZE + 8].copy_from_slice(&65u64.to_be_bytes());
    assert_eq!(err(&f, &p), Error::ManifestMismatch);
}

#[test]
fn record_kinds_are_enforced() {
    let data: Vec<u8> = (0..64).map(|i| i as u8).collect();
    let f = build(&data, 16);

    let mut p = f.pack.clone();
    p[layout::HEADER_LEN] = 9; // KEY_REC kind
    assert_eq!(err(&f, &p), Error::BadKeyRecord);

    let sig_kind_pos = layout::HEADER_LEN + 1 + 4 + 128;
    let mut p = f.pack.clone();
    p[sig_kind_pos] = 9;
    assert_eq!(err(&f, &p), Error::BadSignatureRecord);
}

#[test]
fn block_reorder_delete_duplicate_trailing() {
    let data: Vec<u8> = (0..64).map(|i| i as u8).collect();
    let f = build(&data, 16); // 4 块
    assert_eq!(f.blocks.len(), 4);

    // 交换块 0 / 块 1：第 2 条记录的块号 0 落在期望 1 之后 → 跳号
    let mut p = Vec::new();
    p.extend_from_slice(&f.pack[..f.blocks[0].0]);
    p.extend_from_slice(&f.pack[f.blocks[1].0..f.blocks[1].1]);
    p.extend_from_slice(&f.pack[f.blocks[0].0..f.blocks[0].1]);
    p.extend_from_slice(&f.pack[f.blocks[2].0..]);
    assert_eq!(err(&f, &p), Error::BlockSequence);

    // 删除块 1
    let mut p = Vec::new();
    p.extend_from_slice(&f.pack[..f.blocks[1].0]);
    p.extend_from_slice(&f.pack[f.blocks[2].0..]);
    assert_eq!(err(&f, &p), Error::BlockSequence);

    // 用块 0 的副本占掉块 1 的位置：块号序列 0,0,2,3 → 重复块
    let mut p = Vec::new();
    p.extend_from_slice(&f.pack[..f.blocks[0].0]);
    p.extend_from_slice(&f.pack[f.blocks[0].0..f.blocks[0].1]);
    p.extend_from_slice(&f.pack[f.blocks[0].0..f.blocks[0].1]);
    p.extend_from_slice(&f.pack[f.blocks[2].0..]);
    assert_eq!(err(&f, &p), Error::DuplicateBlock);

    // 截断包尾（少一个块）
    let p = f.pack[..f.blocks[3].0].to_vec();
    assert_eq!(err(&f, &p), Error::MissingBlock);

    // 末尾多 1 字节
    let mut p = f.pack.clone();
    p.push(0);
    assert_eq!(err(&f, &p), Error::TrailingBytes);

    // 末块标志被改
    let last = f.blocks[3].0;
    let mut p = f.pack.clone();
    p[last + 4] = 0; // 末块应 flags=1
    assert_eq!(err(&f, &p), Error::LastFlagMismatch);
}

#[test]
fn byte_flips_are_rejected_everywhere() {
    let data: Vec<u8> = (0..64).map(|i| i as u8).collect();
    let f = build(&data, 16);
    // 逐个字节翻一位，整包任何位置都不许解包成功
    for pos in 0..f.pack.len() {
        let mut p = f.pack.clone();
        p[pos] ^= 0x01;
        assert!(
            pack::unpack(&p, &f.recipient_priv, &f.sender_pub).is_err(),
            "byte {} flipped but pack still unpacked",
            pos
        );
    }
    // 原包仍可解
    ok(&f, &f.pack, &data);
}

#[test]
fn signature_from_wrong_sender_rejected() {
    let data = b"hello yanshu".to_vec();
    let f = build(&data, 16);
    let mut rng = SeedRng::new(b"other-sender");
    let mallory = sm2::keygen(&mut rng);
    let e = pack::unpack(&f.pack, &f.recipient_priv, &mallory.public_key).unwrap_err();
    assert_eq!(e, Error::SignatureMismatch);
}

#[test]
fn wrong_recipient_key_rejected() {
    let data = b"hello yanshu".to_vec();
    let f = build(&data, 16);
    let mut rng = SeedRng::new(b"other-recipient");
    let other = sm2::keygen(&mut rng);
    let e = pack::unpack(&f.pack, &other.private_key, &f.sender_pub).unwrap_err();
    assert_eq!(e, Error::BadKeyRecord);
}
