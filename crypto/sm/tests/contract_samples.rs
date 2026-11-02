//! 契约 `docs/CRYPTO-PACK.md` §15 的样例字节 —— **逐字节**回归测试。
//!
//! 常量直接从契约文档抽取（`tools` 脚本抽取后生成），任何偏差都说明实现与契约不符。
//! 这里的固定 `DK / KDF_SALT / k_enc / k_sig` 只用于测试，生产代码 MUST NOT 出现。

use yanshu_sm::bigint::U256;
use yanshu_sm::pack::{self, PackInput, PackOptions, PackParams};

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

const D_R: &str = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8";

const PB_R: &str = concat!(
    "0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020ccea490ce26775a52dc6ea718cc1aa",
    "600aed05fbf35e084a6632f6072da9ad13",
);

const D_S: &str = "00c1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f";

const PB_S: &str = concat!(
    "04bfd9df73290f50ec16bd184e31c043b6d70fcfd245f76d10ef26b66c9d19b116f425afea1e7e849b2f573e562abab6",
    "5cf47c045c32a2ecc2f23f86519a1ec25d",
);

const DK: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

const KDF_SALT: &str = "000102030405060708090a0b0c0d0e0f";

const K_ENC: &str = "59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21";

const K_SIG: &str = "6cb28d99385c175c94f94e934817663fc176d925dd72b727260dbaae1fb2f96f";

const V1_HEADER: &str = concat!(
    "5953504b010000700000000201010101001000000000000100000000000000050000000000000081000000000000006d",
    "0000005d00000041000102030405060708090a0b0c0d0e0f000000000000004600000000000000000000000000000000",
    "00000000000000000000000000000000",
);

const V1_FULL: &str = concat!(
    "5953504b010000700000000201010101001000000000000100000000000000050000000000000081000000000000006d",
    "0000005d00000041000102030405060708090a0b0c0d0e0f000000000000004600000000000000000000000000000000",
    "0000000000000000000000000000000004bfd9df73290f50ec16bd184e31c043b6d70fcfd245f76d10ef26b66c9d19b1",
    "16f425afea1e7e849b2f573e562abab65cf47c045c32a2ecc2f23f86519a1ec25d0404ebfc718e8d1798620432268e77",
    "feb6415e2ede0e073c0f4f640ecd2e149a73e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e12",
    "4df0f2510ae3cfc74e4eb31b5460e61a55a59c1ad9f8a1b56fcfe425e00b3a6a467344e70dd8f4bfee133f6f597fb2ff",
    "6946147d8c1092763f5d3ceaf6d74f234985186874ecd599472da43a0d5a866014eeb5b072e634f2b72b67ec329825da",
    "fbb48343ff0ba9b0063b1fe02070b21d20c6b3e86781a5e9a5463f72040e925397a7cb97e6b8d25f6065aede90354b01",
    "3789ecbe2c6662730b6faa60bdd0f1578349057322670a37cac504041ce16f3044022063287a23c4ed9288dd091ad234",
    "95200bf98ed1e89cf1ffaf6ecba6013ec5b413022035654a55f88a4a5960318fbebdf6c0585354f2d471c15a7a0b48b1",
    "df91f3c5670000000000000005000000050100000084bf7e96d2590df9b1343a6dd6ea84c381578472ef",
);

const V1_MANIFEST_SEC: &str = concat!(
    "186874ecd599472da43a0d5a866014eeb5b072e634f2b72b67ec329825dafbb48343ff0ba9b0063b1fe02070b21d20c6",
    "b3e86781a5e9a5463f72040e925397a7cb97e6b8d25f6065aede90354b013789ecbe2c6662730b6faa60bdd0f1578349",
    "057322670a37cac504041ce16f",
);

const V1_SIG: &str = concat!(
    "3044022063287a23c4ed9288dd091ad23495200bf98ed1e89cf1ffaf6ecba6013ec5b413022035654a55f88a4a596031",
    "8fbebdf6c0585354f2d471c15a7a0b48b1df91f3c567",
);

const V1_CHUNK0: &str =
    "0000000000000005000000050100000084bf7e96d2590df9b1343a6dd6ea84c381578472ef";

const V2_HEADER: &str = concat!(
    "5953504b01000070000000020101010100000020000000030000000000000050000000000000008100000000000000be",
    "000000ae00000041000102030405060708090a0b0c0d0e0f000000000000004700000000000000000000000000000000",
    "00000000000000000000000000000000",
);

const V2_MANIFEST_SEC: &str = concat!(
    "186874ecd599472da43a0d5a866014bbb5a072c634f2b72967ec329825dafbb4834cfa17ebb017617d833a15d2087fc6",
    "b3e06d8ed183be50641d677ad799716b1503d75234afaccd1212e1b6867a2bb4b4fdff906302486c2f146c1c9898816f",
    "22debef0423bae283565b1f763b192d1254bcb70b3008aaf6bfc2a26ad3b016215dbcf159736e366bf9feac2e3f009ab",
    "893e622ef3fd102d93a43c4a497b6a0fdc05a78b558d89b1b69e75953ee9ba8c48a50b71f6f8f061bde469085bc4",
);

const V2_SIG: &str = concat!(
    "3045022100f88983fb66ae091af5f9ffddc01036ea454f7fdd76c6122ea4869a3a774ddc03022027348d7ac905dffde6",
    "ba2ed6fb8916503629560c23aa24e93580dbe3e0e5e311",
);

const V2_CHUNK0: &str = concat!(
    "00000000000000200000002000000000e53cc98b73ce1316f88b40d72eb4ad007de4c4eb3b998e61423fa7375862a128",
    "ccfc7d2ea872b6d68cba78bdf0d49c5c",
);

const V2_CHUNK1: &str = concat!(
    "000000010000002000000020000000007f6eac8eb153c5a03bda573764795c7106e16c370c917266d7e6aacda5776ac1",
    "7eae13a1a8abf32f27d4986b385173df",
);

const V2_CHUNK2: &str = "00000002000000100000001001000000a06a9b48c7f97001d12c94ce07507a0864c4c34b507721fe15c9c7cae50f0811";

const V2_FULL: &str = concat!(
    "5953504b01000070000000020101010100000020000000030000000000000050000000000000008100000000000000be",
    "000000ae00000041000102030405060708090a0b0c0d0e0f000000000000004700000000000000000000000000000000",
    "0000000000000000000000000000000004bfd9df73290f50ec16bd184e31c043b6d70fcfd245f76d10ef26b66c9d19b1",
    "16f425afea1e7e849b2f573e562abab65cf47c045c32a2ecc2f23f86519a1ec25d0404ebfc718e8d1798620432268e77",
    "feb6415e2ede0e073c0f4f640ecd2e149a73e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e12",
    "4df0f2510ae3cfc74e4eb31b5460e61a55a59c1ad9f8a1b56fcfe425e00b3a6a467344e70dd8f4bfee133f6f597fb2ff",
    "6946147d8c1092763f5d3ceaf6d74f234985186874ecd599472da43a0d5a866014bbb5a072c634f2b72967ec329825da",
    "fbb4834cfa17ebb017617d833a15d2087fc6b3e06d8ed183be50641d677ad799716b1503d75234afaccd1212e1b6867a",
    "2bb4b4fdff906302486c2f146c1c9898816f22debef0423bae283565b1f763b192d1254bcb70b3008aaf6bfc2a26ad3b",
    "016215dbcf159736e366bf9feac2e3f009ab893e622ef3fd102d93a43c4a497b6a0fdc05a78b558d89b1b69e75953ee9",
    "ba8c48a50b71f6f8f061bde469085bc43045022100f88983fb66ae091af5f9ffddc01036ea454f7fdd76c6122ea4869a",
    "3a774ddc03022027348d7ac905dffde6ba2ed6fb8916503629560c23aa24e93580dbe3e0e5e311000000000000002000",
    "00002000000000e53cc98b73ce1316f88b40d72eb4ad007de4c4eb3b998e61423fa7375862a128ccfc7d2ea872b6d68c",
    "ba78bdf0d49c5c000000010000002000000020000000007f6eac8eb153c5a03bda573764795c7106e16c370c917266d7",
    "e6aacda5776ac17eae13a1a8abf32f27d4986b385173df00000002000000100000001001000000a06a9b48c7f97001d1",
    "2c94ce07507a0864c4c34b507721fe15c9c7cae50f0811",
);

const V3_WRAPPED: &str = concat!(
    "0404ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73e858f9d81e5430a57b36daab8f950a",
    "3c64e6ee6a63094d99283aff767e124df0f2510ae3cfc74e4eb31b5460e61a55a59c1ad9f8a1b56fcfe425e00b3a6a46",
    "7344e70dd8f4bfee133f6f597fb2ff6946147d8c1092763f5d3ceaf6d74f234985",
);

fn params() -> PackParams {
    PackParams {
        dk: h(DK).try_into().unwrap(),
        kdf_salt: h(KDF_SALT).try_into().unwrap(),
        k_enc: u256(K_ENC),
        k_sig: u256(K_SIG),
    }
}

fn v1_pack() -> Vec<u8> {
    let recipient: [u8; 65] = h(PB_R).try_into().unwrap();
    let sender: [u8; 32] = h(D_S).try_into().unwrap();
    let data = b"hello";
    let recipient64: [u8; 64] = recipient[1..].try_into().unwrap();
    let input = PackInput {
        recipient_public: &recipient64,
        sender_private: &sender,
        name: "hi.txt",
        mime: "text/plain",
        block_size: 1_048_576,
        data,
    };
    let options = PackOptions {
        ext: "txt",
        created_at_ms: 1_767_225_600_000,
    };
    pack::pack_with_params(&input, &options, &params()).expect("pack")
}

fn v2_pack() -> Vec<u8> {
    let recipient: [u8; 65] = h(PB_R).try_into().unwrap();
    let sender: [u8; 32] = h(D_S).try_into().unwrap();
    let data: Vec<u8> = (0u8..0x50).collect();
    let recipient64: [u8; 64] = recipient[1..].try_into().unwrap();
    let input = PackInput {
        recipient_public: &recipient64,
        sender_private: &sender,
        name: "multi.bin",
        mime: "application/octet-stream",
        block_size: 32,
        data: &data,
    };
    let options = PackOptions {
        ext: "bin",
        created_at_ms: 1_767_225_600_000,
    };
    pack::pack_with_params(&input, &options, &params()).expect("pack")
}

#[test]
fn v1_minimal_single_chunk_matches_contract() {
    let envelope = v1_pack();
    assert_eq!(envelope.len(), 522, "ENVELOPE_LEN");
    assert_eq!(hex(&envelope), V1_FULL, "§15.2 完整包");
    assert_eq!(hex(&envelope[..112]), V1_HEADER, "§15.2 HEADER");
    assert_eq!(hex(&envelope[112..177]), PB_S, "§15.2 SENDER_PUB");
    let manifest_sec = &envelope[112 + 65 + 129..112 + 65 + 129 + 109];
    assert_eq!(hex(manifest_sec), V1_MANIFEST_SEC, "§15.2 MANIFEST_SEC");
    assert_eq!(
        hex(&envelope[112 + 65 + 129 + 109..112 + 65 + 129 + 109 + 70]),
        V1_SIG,
        "§15.2 SIG_SEC"
    );
    assert_eq!(hex(&envelope[485..]), V1_CHUNK0, "§15.2 块记录");
}

#[test]
fn v1_unpack_roundtrip() {
    let envelope = v1_pack();
    let d_r: [u8; 32] = h(D_R).try_into().unwrap();
    let out = pack::unpack_with_code(&envelope, &d_r, "AWQW").expect("unpack");
    assert_eq!(out.data, b"hello");
    assert_eq!(out.manifest.name, "hi.txt");
    assert_eq!(out.manifest.mime, "text/plain");
    assert_eq!(out.manifest.ext, "txt");
    assert_eq!(out.manifest.block_count, 1);
    assert_eq!(out.manifest.file_size, 5);
    assert_eq!(out.sender_code, "AWQW");
}

#[test]
fn v2_multi_chunk_matches_contract() {
    let envelope = v2_pack();
    assert_eq!(envelope.len(), 743, "ENVELOPE_LEN");
    assert_eq!(hex(&envelope), V2_FULL, "§15.3 完整包");
    assert_eq!(hex(&envelope[..112]), V2_HEADER, "§15.3 HEADER");
    let man_off = 112 + 65 + 129;
    let man_len = 190;
    assert_eq!(
        hex(&envelope[man_off..man_off + man_len]),
        V2_MANIFEST_SEC,
        "§15.3 MANIFEST_SEC"
    );
    assert_eq!(
        hex(&envelope[man_off + man_len..man_off + man_len + 71]),
        V2_SIG,
        "§15.3 SIG_SEC"
    );
    let chunk_off = man_off + man_len + 71;
    assert_eq!(hex(&envelope[chunk_off..chunk_off + 64]), V2_CHUNK0);
    assert_eq!(hex(&envelope[chunk_off + 64..chunk_off + 128]), V2_CHUNK1);
    assert_eq!(hex(&envelope[chunk_off + 128..]), V2_CHUNK2);
}

#[test]
fn v2_unpack_roundtrip_and_digests() {
    let envelope = v2_pack();
    let d_r: [u8; 32] = h(D_R).try_into().unwrap();
    let out = pack::unpack_with_code(&envelope, &d_r, "AWQW").expect("unpack");
    let expect: Vec<u8> = (0u8..0x50).collect();
    assert_eq!(out.data, expect);
    assert_eq!(out.manifest.digests.len(), 3);
    assert_eq!(
        hex(&out.manifest.digests[0]),
        "fa34635f1d3ac2729ac5987eb59e01928457f325b4b51ca85a177813c5c5ddf7"
    );
    assert_eq!(
        hex(&out.manifest.digests[1]),
        "778cfd21a404c276d1efdf3137c41b3b89d7f003b192efde1fb0c053b7028e9a"
    );
    assert_eq!(
        hex(&out.manifest.digests[2]),
        "20c717e09714e6191630c4b93a398e49346f3e69a862f38c609e92a0f0f2676d"
    );
}

#[test]
fn v3_wrapped_key_matches_contract() {
    // WRAPPED_KEY 是 V1 包里 offset 112+65 起 129 字节
    let envelope = v1_pack();
    assert_eq!(
        hex(&envelope[177..177 + 129]),
        V3_WRAPPED,
        "§15.4 WRAPPED_KEY"
    );
}

#[test]
fn v4_signature_matches_contract() {
    let envelope = v1_pack();
    let man_off = 112 + 65 + 129;
    let man_len = 109;
    assert_eq!(
        hex(&envelope[man_off + man_len..man_off + man_len + 70]),
        V1_SIG,
        "§15.5 SIG_SEC"
    );
}

#[test]
fn tampering_breaks_either_auth_or_signature() {
    let envelope = v1_pack();
    let d_r: [u8; 32] = h(D_R).try_into().unwrap();
    for pos in [8usize, 16, 56, 112, 177, 306, 400, 500] {
        let mut bad = envelope.clone();
        bad[pos] ^= 0x01;
        assert!(
            pack::unpack_with_code(&bad, &d_r, "AWQW").is_err(),
            "byte {} tampered but unpacked",
            pos
        );
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
