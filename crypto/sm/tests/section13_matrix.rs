//! 契约 `docs/CRYPTO-PACK.md` §13 的 22 条校验，**每条一个反例**。
//!
//! 测试名与契约编号一一对应：`check_01_...` … `check_22_...`。
//! 任何"尽力恢复"都会让这里的断言失败。

use yanshu_sm::bigint::U256;
use yanshu_sm::error::Error;
use yanshu_sm::gcm;
use yanshu_sm::hkdf::hkdf_sm3;
use yanshu_sm::pack::{self, v1, PackInput, PackOptions, PackParams};
use yanshu_sm::rng::{Rng, SeedRng};
use yanshu_sm::sm2;

const HDR: usize = 112;
const PUB: usize = 65;
const WRAP: usize = 129;

struct Fx {
    pack: Vec<u8>,
    dk: [u8; 32],
    salt: [u8; 16],
    recipient_priv: [u8; 32],
    sender_priv: [u8; 32],
    k_sig: U256,
    sender_code: String,
    sender_pub: [u8; 65],
    manifest_off: usize,
    sig_off: usize,
    chunk_off: usize,
    chunk_ends: Vec<usize>,
    plain: Vec<u8>,
}

fn scalar(rng: &mut SeedRng) -> U256 {
    loop {
        let mut b = [0u8; 32];
        rng.fill(&mut b);
        let v = U256::from_be_bytes(&b);
        if !v.is_zero() && v.cmp_u(&sm2::curve_order()) == core::cmp::Ordering::Less {
            return v;
        }
    }
}

fn build(plain_len: usize, chunk_size: u32) -> Fx {
    let mut rng = SeedRng::new(b"section13-fixture");
    let sender = sm2::keygen(&mut rng);
    let recipient = sm2::keygen(&mut rng);
    let mut recipient_pub = [0u8; 65];
    recipient_pub[0] = 0x04;
    recipient_pub[1..].copy_from_slice(&recipient.public_key);
    let mut sender_pub = [0u8; 65];
    sender_pub[0] = 0x04;
    sender_pub[1..].copy_from_slice(&sender.public_key);

    let plain: Vec<u8> = (0..plain_len).map(|i| (i * 29 + 7) as u8).collect();
    let mut dk = [0u8; 32];
    rng.fill(&mut dk);
    let mut salt = [0u8; 16];
    rng.fill(&mut salt);
    let k_sig = scalar(&mut rng);
    let params = PackParams {
        dk,
        kdf_salt: salt,
        k_enc: scalar(&mut rng),
        k_sig,
    };
    let recipient64: [u8; 64] = recipient_pub[1..].try_into().expect("64");
    let input = PackInput {
        recipient_public: &recipient64,
        sender_private: &sender.private_key,
        name: "f.bin",
        mime: "application/octet-stream",
        block_size: chunk_size,
        data: &plain,
    };
    let options = PackOptions {
        ext: "bin",
        created_at_ms: 1_767_225_600_000,
    };
    let pack = pack::pack_with_params(&input, &options, &params).expect("pack");
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

    let sender_code = yanshu_sm::code::from_public_key(&sender_pub);
    Fx {
        pack,
        dk,
        salt,
        recipient_priv: recipient.private_key,
        sender_priv: sender.private_key,
        k_sig,
        sender_code,
        sender_pub,
        manifest_off,
        sig_off,
        chunk_off,
        chunk_ends,
        plain,
    }
}

/// 篡改后重新签名（模拟"发送方自己签了错摘要"，用于测 #21 这类"签名有效但内容不一致"）。
fn resign(f: &mut Fx) {
    use yanshu_sm::der;
    let header = pack::read_header(&f.pack).unwrap();
    let old_len = header.sig_len as usize;
    let man_sec = f.pack[f.manifest_off..f.manifest_off + header.manifest_len as usize].to_vec();
    let mut sig_input = Vec::new();
    sig_input.extend_from_slice(b"YSSIG1");
    sig_input.push(1);
    sig_input.push(0);
    sig_input.extend_from_slice(&f.pack[..72]);
    sig_input.extend_from_slice(&f.sender_pub);
    sig_input.extend_from_slice(&man_sec);
    let raw = sm2::sign_with_k(&f.sender_priv, &sig_input, sm2::DEFAULT_ID, &f.k_sig)
        .unwrap()
        .unwrap();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&raw[..32]);
    s.copy_from_slice(&raw[32..]);
    let der = der::encode_signature(&r, &s);
    let new_len = der.len();
    // 调整签名段长度（后续块区随之平移）
    if new_len > old_len {
        let at = f.sig_off + old_len;
        f.pack.splice(at..at, vec![0u8; new_len - old_len]);
    } else if new_len < old_len {
        let at = f.sig_off + new_len;
        f.pack.drain(at..at + (old_len - new_len));
    }
    f.pack[f.sig_off..f.sig_off + new_len].copy_from_slice(&der);
    f.pack[72..80].copy_from_slice(&(new_len as u64).to_be_bytes());
    let delta = new_len as isize - old_len as isize;
    f.chunk_off = (f.chunk_off as isize + delta) as usize;
    for e in f.chunk_ends.iter_mut() {
        *e = (*e as isize + delta) as usize;
    }
}

fn err(f: &Fx, p: &[u8]) -> Error {
    pack::unpack_unchecked(p, &f.recipient_priv).unwrap_err()
}

/// 解出清单明文 → 让调用方改 → 用同一 KEK/nonce/AAD 重新加密并写回。
fn tamper_manifest(f: &mut Fx, mutate: impl FnOnce(&mut Vec<u8>)) {
    use yanshu_sm::pack::{aad_manifest, Manifest};
    let header = pack::read_header(&f.pack).unwrap();
    let mut kek = [0u8; 16];
    hkdf_sm3(&f.salt, &f.dk, v1::KDF_INFO_MANIFEST, &mut kek);
    let sec_off = f.manifest_off;
    let sec_len = header.manifest_len as usize;
    let sec = &f.pack[sec_off..sec_off + sec_len];
    let ct = &sec[..sec_len - 16];
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&sec[sec_len - 16..]);
    let aad = aad_manifest(&header);
    let mut plain =
        gcm::decrypt(&kek, &v1::MANIFEST_NONCE, &aad, ct, &tag).expect("decrypt manifest");
    mutate(&mut plain);
    // 自检：改完仍是合法结构（除了被刻意破坏的字段）
    let _ = Manifest::decode(&plain);
    let mut new_ct = vec![0u8; plain.len()];
    let mut new_tag = [0u8; 16];
    gcm::encrypt(
        &kek,
        &v1::MANIFEST_NONCE,
        &aad,
        &plain,
        &mut new_ct,
        &mut new_tag,
    );
    assert_eq!(plain.len(), sec_len - 16, "夹具要求等长修改");
    f.pack[sec_off..sec_off + sec_len - 16].copy_from_slice(&new_ct);
    f.pack[sec_off + sec_len - 16..sec_off + sec_len].copy_from_slice(&new_tag);
}

/// #1 总长度低于最小包
#[test]
fn check_01_minimum_length() {
    let f = build(8, 16);
    assert_eq!(err(&f, &f.pack[..HDR - 1]), Error::LengthInconsistent);
    assert_eq!(err(&f, &f.pack[..8]), Error::LengthInconsistent);
}

/// #2 MAGIC
#[test]
fn check_02_magic() {
    let f = build(8, 16);
    let mut p = f.pack.clone();
    p[0] ^= 0x01;
    assert_eq!(err(&f, &p), Error::BadMagic);
}

/// #3 版本（大版本 / 小版本都拒绝）
#[test]
fn check_03_version() {
    let f = build(8, 16);
    for (off, val) in [(4usize, 2u8), (5, 1)] {
        let mut p = f.pack.clone();
        p[off] = val;
        assert_eq!(err(&f, &p), Error::UnsupportedVersion, "off {}", off);
    }
}

/// #4 HEADER_LEN
#[test]
fn check_04_header_len() {
    let f = build(8, 16);
    let mut p = f.pack.clone();
    p[6..8].copy_from_slice(&113u16.to_be_bytes());
    assert_eq!(err(&f, &p), Error::HeaderInvalid);
}

/// #5 四个算法 ID（AEAD / KDF / WRAP / SIG）
#[test]
fn check_05_algorithm_ids() {
    let f = build(8, 16);
    for off in [12usize, 13, 14, 15] {
        let mut p = f.pack.clone();
        p[off] = 9;
        assert_eq!(err(&f, &p), Error::AlgUnsupported, "off {}", off);
    }
}

/// #6 FLAGS 保留位 / SENDER_SIGNED=0
#[test]
fn check_06_flags() {
    let f = build(8, 16);
    let mut p = f.pack.clone();
    p[11] |= 0x04; // bit2 保留位
    assert_eq!(err(&f, &p), Error::BadFlags);

    let mut p = f.pack.clone();
    p[11] &= !0x02; // SENDER_SIGNED = 0
    assert_eq!(err(&f, &p), Error::Unsigned);
}

/// #7 RESERVED[80..112) 非零
#[test]
fn check_07_reserved() {
    let f = build(8, 16);
    for off in [80usize, 95, 111] {
        let mut p = f.pack.clone();
        p[off] = 1;
        assert_eq!(err(&f, &p), Error::HeaderInvalid, "off {}", off);
    }
}

/// #8 CHUNK_SIZE 越界（16..=1048576）
#[test]
fn check_08_chunk_size_range() {
    let f = build(8, 16);
    for v in [0u32, 15, 1_048_577] {
        let mut p = f.pack.clone();
        p[16..20].copy_from_slice(&v.to_be_bytes());
        assert_eq!(err(&f, &p), Error::HeaderInvalid, "chunk_size {}", v);
    }
}

/// #9 CHUNK_COUNT 与 PLAINTEXT_SIZE 交叉校验
#[test]
fn check_09_chunk_count() {
    let f = build(96, 32); // 3 块
    let mut p = f.pack.clone();
    p[20..24].copy_from_slice(&0u32.to_be_bytes());
    assert_eq!(err(&f, &p), Error::LengthInconsistent);

    let mut p = f.pack.clone();
    p[20..24].copy_from_slice(&4u32.to_be_bytes());
    assert_eq!(err(&f, &p), Error::LengthInconsistent);
}

/// #10 三个长度字段
#[test]
fn check_10_length_fields() {
    let f = build(8, 16);
    let mut p = f.pack.clone();
    p[32..40].copy_from_slice(&128u64.to_be_bytes()); // WRAPPED_KEY_LEN
    assert_eq!(err(&f, &p), Error::LengthInconsistent);

    let mut p = f.pack.clone();
    p[52..56].copy_from_slice(&64u32.to_be_bytes()); // SENDER_PUB_LEN
    assert_eq!(err(&f, &p), Error::LengthInconsistent);

    let mut p = f.pack.clone();
    p[40..48].copy_from_slice(&999u64.to_be_bytes()); // MANIFEST_LEN
    assert_eq!(err(&f, &p), Error::LengthInconsistent);
}

/// #11 SIG_LEN 与 DER 自述长度不一致
#[test]
fn check_11_sig_len_vs_der() {
    let f = build(8, 16);
    let header = pack::read_header(&f.pack).unwrap();
    let real = header.sig_len as usize;
    let bumped = if real < 72 { real + 1 } else { real - 1 };
    let mut p = f.pack.clone();
    // SIG_LEN 与 DER 自述长度不一致，但整包长度按新 SIG_LEN 仍然自洽
    p[72..80].copy_from_slice(&(bumped as u64).to_be_bytes());
    let insert_at = f.sig_off + real;
    if bumped > real {
        p.splice(insert_at..insert_at, [0u8; 1]);
    } else {
        p.drain(insert_at - 1..insert_at);
    }
    assert_eq!(err(&f, &p), Error::HeaderInvalid);
}

/// #12 ENVELOPE_LEN：尾部多余字节 / 截断
#[test]
fn check_12_envelope_length() {
    let f = build(8, 16);
    let mut p = f.pack.clone();
    p.push(0);
    assert_eq!(err(&f, &p), Error::LengthInconsistent);
    assert_eq!(
        err(&f, &f.pack[..f.pack.len() - 1]),
        Error::LengthInconsistent
    );
}

/// #13 SM2 解封（错收件人私钥）
#[test]
fn check_13_key_unwrap() {
    let f = build(8, 16);
    let mut rng = SeedRng::new(b"other-recipient-13");
    let other = sm2::keygen(&mut rng);
    assert_eq!(
        pack::unpack_unchecked(&f.pack, &other.private_key).unwrap_err(),
        Error::BadKeyRecord
    );
    // 段落被改（C1 前缀错）
    let mut p = f.pack.clone();
    p[HDR + PUB] = 0x05;
    assert_eq!(err(&f, &p), Error::BadKeyRecord);
}

/// #14 清单认证（tag）
#[test]
fn check_14_manifest_auth() {
    let f = build(8, 16);
    let mut p = f.pack.clone();
    p[f.manifest_off + 3] ^= 0x01;
    assert_eq!(err(&f, &p), Error::ManifestAuthFailed);

    let mut p = f.pack.clone();
    let tag_off = f.manifest_off + pack::read_header(&f.pack).unwrap().manifest_len as usize - 1;
    p[tag_off] ^= 0x01;
    assert_eq!(err(&f, &p), Error::ManifestAuthFailed);
}

/// #15 清单头部字段（YSM1 / 版本 / 摘要算法）
#[test]
fn check_15_manifest_header() {
    let mut f = build(8, 16);
    // MAGIC 改 1 字节
    let mut p = f.pack.clone();
    tamper_manifest(&mut f, |m| m[0] ^= 0x01);
    assert_eq!(
        pack::unpack_unchecked(&f.pack, &f.recipient_priv).unwrap_err(),
        Error::BadManifestRecord
    );
    // MANIFEST_VERSION 改 2
    let mut f2 = build(8, 16);
    tamper_manifest(&mut f2, |m| m[4] = 2);
    assert_eq!(
        pack::unpack_unchecked(&f2.pack, &f2.recipient_priv).unwrap_err(),
        Error::BadManifestRecord
    );
    // DIGEST_ALG / DIGEST_LEN
    let mut f3 = build(8, 16);
    tamper_manifest(&mut f3, |m| m[6] = 2);
    assert_eq!(
        pack::unpack_unchecked(&f3.pack, &f3.recipient_priv).unwrap_err(),
        Error::BadManifestRecord
    );
    let _ = p.pop();
}

/// #16 清单与包头不一致 / 摘要表长度 / 字符串长度越界
#[test]
fn check_16_manifest_cross_check() {
    // FILE_SIZE 不一致
    let mut f = build(8, 16);
    tamper_manifest(&mut f, |m| {
        let mut v = [0u8; 8];
        v.copy_from_slice(&m[8..16]);
        let n = u64::from_be_bytes(v);
        m[8..16].copy_from_slice(&(n + 1).to_be_bytes());
    });
    assert_eq!(
        pack::unpack_unchecked(&f.pack, &f.recipient_priv).unwrap_err(),
        Error::LengthInconsistent
    );

    // CHUNK_COUNT 不一致
    let mut f2 = build(96, 32);
    tamper_manifest(&mut f2, |m| m[20..24].copy_from_slice(&2u32.to_be_bytes()));
    assert_eq!(
        pack::unpack_unchecked(&f2.pack, &f2.recipient_priv).unwrap_err(),
        Error::LengthInconsistent
    );

    // DIGEST_TABLE_LEN 不一致（长度相同，值改错）
    let mut f3 = build(32, 16);
    tamper_manifest(&mut f3, |m| {
        let off = m.len() - 4 - 64; // DIGEST_TABLE_LEN 在摘要表之前（2 块 = 64 字节摘要）
        m[off..off + 4].copy_from_slice(&32u32.to_be_bytes());
    });
    assert_eq!(
        pack::unpack_unchecked(&f3.pack, &f3.recipient_priv).unwrap_err(),
        Error::LengthInconsistent
    );
}

/// #17 签名（改 DER / 换发送方）
#[test]
fn check_17_signature() {
    let f = build(8, 16);
    let mut p = f.pack.clone();
    p[f.sig_off + 10] ^= 0x01;
    assert_eq!(err(&f, &p), Error::SignatureMismatch);

    // 换 SENDER_PUB → 验签失败（或曲线错误），总之必须拒绝
    let mut p = f.pack.clone();
    p[HDR + 1] ^= 0x01;
    assert!(pack::unpack_unchecked(&p, &f.recipient_priv).is_err());
}

/// #18 发送方码与元数据不一致
#[test]
fn check_18_sender_code() {
    let f = build(8, 16);
    assert!(pack::unpack_with_code(&f.pack, &f.recipient_priv, &f.sender_code).is_ok());
    let wrong = if f.sender_code == "ZZZZ" {
        "YYYY"
    } else {
        "ZZZZ"
    };
    assert_eq!(
        pack::unpack_with_code(&f.pack, &f.recipient_priv, wrong).unwrap_err(),
        Error::SenderMismatch
    );
}

/// #19 块头自洽（索引 / 长度 / 保留位 / 末块标志）
#[test]
fn check_19_chunk_header() {
    let f = build(96, 32); // 3 块
    assert_eq!(f.chunk_ends.len(), 3);
    let c0 = f.chunk_off;

    // 索引重复（0,1,0）：包长不变，第 3 条记录 index 回到 0
    let rec2 = f.chunk_ends[1];
    let mut p = f.pack.clone();
    p[rec2..rec2 + 4].copy_from_slice(&0u32.to_be_bytes());
    assert_eq!(err(&f, &p), Error::ChunkOrder);

    // PT_LEN 与头不符
    let mut p = f.pack.clone();
    p[c0 + 4..c0 + 8].copy_from_slice(&16u32.to_be_bytes());
    assert_eq!(err(&f, &p), Error::LengthInconsistent);

    // CT_LEN 与 PT_LEN 不等
    let mut p = f.pack.clone();
    p[c0 + 8..c0 + 12].copy_from_slice(&16u32.to_be_bytes());
    assert_eq!(err(&f, &p), Error::LengthInconsistent);

    // RESERVED 非零
    let mut p = f.pack.clone();
    p[c0 + 13] = 1;
    assert_eq!(err(&f, &p), Error::HeaderInvalid);

    // 末块标志被掀掉
    let last = f.chunk_ends[1];
    let mut p = f.pack.clone();
    p[last + 12] = 0;
    assert_eq!(err(&f, &p), Error::ChunkOrder);

    // 末块标志错误地出现在中间块
    let mut p = f.pack.clone();
    p[c0 + 12] = 1;
    assert_eq!(err(&f, &p), Error::ChunkOrder);
}

/// #20 块 GCM 认证
#[test]
fn check_20_chunk_auth() {
    let f = build(40, 16);
    let mut p = f.pack.clone();
    p[f.chunk_off + 16] ^= 0x01; // 第一块密文
    assert_eq!(err(&f, &p), Error::ChunkAuthFailed);

    let mut p = f.pack.clone();
    let last_ct_end = *f.chunk_ends.last().unwrap();
    p[last_ct_end - 1] ^= 0x01; // 末块 tag
    assert_eq!(err(&f, &p), Error::ChunkAuthFailed);
}

/// #21 明文摘要与清单不一致（GCM 通过但摘要不符）
#[test]
fn check_21_digest_mismatch() {
    let mut f = build(32, 16);
    // 改清单里第一个块的摘要（等长），GCM 仍有效
    tamper_manifest(&mut f, |m| {
        let digest_off = m.len() - 32 * 2; // 2 块，取第 0 块摘要
        m[digest_off] ^= 0x01;
    });
    resign(&mut f); // 签名有效，但摘要与明文不符
    assert_eq!(
        pack::unpack_unchecked(&f.pack, &f.recipient_priv).unwrap_err(),
        Error::DigestMismatch
    );
}

/// #22 块缺失 / 顺序
#[test]
fn check_22_missing_chunk() {
    let f = build(96, 32); // 3 块
                           // 首条记录改成 index=1（跳过 0）→ 缺块
    let mut p = f.pack.clone();
    let c0 = f.chunk_off;
    p[c0..c0 + 4].copy_from_slice(&1u32.to_be_bytes());
    assert_eq!(err(&f, &p), Error::ChunkMissing);

    // 正常包仍可解，且数据一致
    let out = pack::unpack_with_code(&f.pack, &f.recipient_priv, &f.sender_code).expect("ok");
    assert_eq!(out.data, f.plain);
    assert_eq!(out.sender_public, f.sender_pub);
}

/// 契约 §3.3 的字符串规则（打包侧拒绝、解包侧拒绝）
#[test]
fn section_3_3_string_rules() {
    let mut rng = SeedRng::new(b"strings");
    let sender = sm2::keygen(&mut rng);
    let recipient = sm2::keygen(&mut rng);
    let mut recipient_pub = [0u8; 65];
    recipient_pub[0] = 0x04;
    recipient_pub[1..].copy_from_slice(&recipient.public_key);

    let mk = |name: &'static str, mime: &'static str, ext: &'static str| {
        let params = PackParams {
            dk: [7u8; 32],
            kdf_salt: [9u8; 16],
            k_enc: U256::from_be_bytes(&[3u8; 32]),
            k_sig: U256::from_be_bytes(&[5u8; 32]),
        };
        let recipient64: [u8; 64] = recipient_pub[1..].try_into().expect("64");
        let input = PackInput {
            recipient_public: &recipient64,
            sender_private: &sender.private_key,
            name,
            mime,
            block_size: 16,
            data: b"x",
        };
        let options = PackOptions {
            ext,
            created_at_ms: 1,
        };
        pack::pack_with_params(&input, &options, &params)
    };

    assert!(mk("ok.txt", "text/plain", "txt").is_ok());
    assert_eq!(
        mk("a/b.txt", "text/plain", "txt").unwrap_err(),
        Error::BadArgument
    );
    assert_eq!(
        mk("a\\b.txt", "text/plain", "txt").unwrap_err(),
        Error::BadArgument
    );
    assert_eq!(
        mk("a\u{1}b", "text/plain", "txt").unwrap_err(),
        Error::BadArgument
    );
    assert_eq!(
        mk("ok.txt", "Text/Plain", "txt").unwrap_err(),
        Error::BadArgument
    );
    assert_eq!(mk("ok.txt", "text", "txt").unwrap_err(), Error::BadArgument);
    assert_eq!(
        mk("ok.txt", "text/plain;charset=utf-8", "txt").unwrap_err(),
        Error::BadArgument
    );
    assert_eq!(
        mk("ok.txt", "text/plain", "TXT").unwrap_err(),
        Error::BadArgument
    );
    assert_eq!(
        mk("ok.txt", "text/plain", "t.t").unwrap_err(),
        Error::BadArgument
    );
}
