//! 流式接口与整包接口**逐字节相同**（契约 §15 样例 + 多块 + 乱序/篡改负例）。

use yanshu_sm::bigint::U256;
use yanshu_sm::error::Error;
use yanshu_sm::pack::{self, PackInput, PackParams, PackStream};

fn h(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}
fn u256(s: &str) -> U256 {
    let v = h(s);
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    U256::from_be_bytes(&a)
}

const PB_R: &str = concat!(
    "0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020ccea490ce26775a52dc6ea718cc1aa",
    "600aed05fbf35e084a6632f6072da9ad13",
);
const D_S: &str = "00c1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f";
const D_R: &str = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8";
const DK: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const KDF_SALT: &str = "000102030405060708090a0b0c0d0e0f";
const K_ENC: &str = "59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21";
const K_SIG: &str = "6cb28d99385c175c94f94e934817663fc176d925dd72b727260dbaae1fb2f96f";

fn params() -> PackParams {
    PackParams {
        dk: h(DK).try_into().unwrap(),
        kdf_salt: h(KDF_SALT).try_into().unwrap(),
        k_enc: u256(K_ENC),
        k_sig: u256(K_SIG),
    }
}

/// 用流式接口产出一个完整包，用于与整包比较。
#[allow(clippy::too_many_arguments)]
fn stream_pack(
    recipient: &[u8; 65],
    sender: &[u8; 32],
    name: &str,
    mime: &str,
    ext: &str,
    created_at: u64,
    chunk_size: u32,
    data: &[u8],
    p: &PackParams,
) -> Vec<u8> {
    let mut s = PackStream::begin_with_params(
        &recipient[1..].try_into().unwrap(),
        sender,
        name,
        mime,
        ext,
        created_at,
        chunk_size,
        data.len() as u64,
        p,
    )
    .expect("begin");
    // 分两段喂，验证增量哈希与一次喂入等价
    let mid = data.len() / 2;
    s.hash_update(&data[..mid]).unwrap();
    s.hash_update(&data[mid..]).unwrap();
    s.make_prelude().expect("prelude");
    let mut out = s.prelude().to_vec();
    for i in 0..s.chunk_count() {
        let start = i as usize * chunk_size as usize;
        let len = s.chunk_len(i) as usize;
        let mut rec = Vec::new();
        s.chunk(i, &data[start..start + len], &mut rec).unwrap();
        out.extend_from_slice(&rec);
    }
    out
}

#[test]
fn streaming_equals_whole_pack_v1() {
    let recipient: [u8; 65] = h(PB_R).try_into().unwrap();
    let sender: [u8; 32] = h(D_S).try_into().unwrap();
    let data = b"hello";
    let whole = pack::pack_with_params(
        &PackInput {
            recipient_public: &recipient,
            sender_private: &sender,
            name: "hi.txt",
            mime: "text/plain",
            ext: "txt",
            created_at_ms: 1_767_225_600_000,
            chunk_size: 1_048_576,
            data,
        },
        &params(),
    )
    .unwrap();
    let streamed = stream_pack(
        &recipient,
        &sender,
        "hi.txt",
        "text/plain",
        "txt",
        1_767_225_600_000,
        1_048_576,
        data,
        &params(),
    );
    assert_eq!(streamed, whole, "V1：流式与整包必须逐字节相同");
    assert_eq!(streamed.len(), 522, "契约 §15.2 V1 = 522 字节");
}

#[test]
fn streaming_equals_whole_pack_multi_chunk() {
    let recipient: [u8; 65] = h(PB_R).try_into().unwrap();
    let sender: [u8; 32] = h(D_S).try_into().unwrap();
    let data: Vec<u8> = (0u8..0x50).collect();
    let whole = pack::pack_with_params(
        &PackInput {
            recipient_public: &recipient,
            sender_private: &sender,
            name: "multi.bin",
            mime: "application/octet-stream",
            ext: "bin",
            created_at_ms: 1_767_225_600_000,
            chunk_size: 32,
            data: &data,
        },
        &params(),
    )
    .unwrap();
    let streamed = stream_pack(
        &recipient,
        &sender,
        "multi.bin",
        "application/octet-stream",
        "bin",
        1_767_225_600_000,
        32,
        &data,
        &params(),
    );
    assert_eq!(streamed, whole, "V2：流式与整包必须逐字节相同");
    assert_eq!(streamed.len(), 743, "契约 §15.2 V2 = 743 字节");
}

#[test]
fn streaming_unpack_matches_whole_pack() {
    let recipient: [u8; 65] = h(PB_R).try_into().unwrap();
    let sender: [u8; 32] = h(D_S).try_into().unwrap();
    let data: Vec<u8> = (0u8..0x50).collect();
    let whole = pack::pack_with_params(
        &PackInput {
            recipient_public: &recipient,
            sender_private: &sender,
            name: "multi.bin",
            mime: "application/octet-stream",
            ext: "bin",
            created_at_ms: 1_767_225_600_000,
            chunk_size: 32,
            data: &data,
        },
        &params(),
    )
    .unwrap();

    let d_r: [u8; 32] = h(D_R).try_into().unwrap();
    // prelude = 112 + 65 + 129 + MANIFEST_LEN + SIG_LEN，从包头读
    let header = &whole[..112];
    let manifest_len = u64::from_be_bytes(header[40..48].try_into().unwrap()) as usize;
    let sig_len = u64::from_be_bytes(header[72..80].try_into().unwrap()) as usize;
    let prelude_len = 112 + 65 + 129 + manifest_len + sig_len;

    let mut u = yanshu_sm::pack::open_stream(&whole[..prelude_len], &d_r).expect("open_stream");
    assert_eq!(u.sender_code(), "AWQW");
    assert_eq!(u.chunk_count(), 3);
    let mut out = Vec::new();
    let mut pos = prelude_len;
    while !u.done() {
        let idx = (pos - prelude_len) as u32; // 只为断言顺序
        let _ = idx;
        let pt_len = u32::from_be_bytes(whole[pos + 4..pos + 8].try_into().unwrap()) as usize;
        let rec_len = 16 + pt_len + 16;
        let mut chunk = Vec::new();
        u.chunk(&whole[pos..pos + rec_len], &mut chunk).unwrap();
        out.extend_from_slice(&chunk);
        pos += rec_len;
    }
    assert_eq!(out, data, "流式解包结果必须等于原文");

    // 乱序：先喂第 2 块 → CHUNK_ORDER
    let mut u2 = yanshu_sm::pack::open_stream(&whole[..prelude_len], &d_r).unwrap();
    let first_len = 16 + u2.chunk_len(0) as usize + 16;
    let second_start = prelude_len + first_len;
    let second_pt = u32::from_be_bytes(
        whole[second_start + 4..second_start + 8]
            .try_into()
            .unwrap(),
    ) as usize;
    let second_rec = &whole[second_start..second_start + 16 + second_pt + 16];
    assert_eq!(
        u2.chunk(second_rec, &mut Vec::new()).unwrap_err(),
        Error::ChunkOrder
    );

    // 篡改 tag → CHUNK_AUTH_FAILED
    let mut u3 = yanshu_sm::pack::open_stream(&whole[..prelude_len], &d_r).unwrap();
    let mut bad = whole[prelude_len..prelude_len + first_len].to_vec();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert_eq!(
        u3.chunk(&bad, &mut Vec::new()).unwrap_err(),
        Error::ChunkAuthFailed
    );
}
