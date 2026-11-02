//! 契约 §10.2 / API §1.3 的签名口径逐条锁死（Core 服务端验签要用同一套）。

use yanshu_sm::bigint::U256;
use yanshu_sm::pack::v1;
use yanshu_sm::sm2;
use yanshu_sm::sm3::sm3;

const PB_S_HEX: &str = "04bfd9df73290f50ec16bd184e31c043b6d70fcfd245f76d10ef26b66c9d19b116f425afea1e7e849b2f573e562abab65cf47c045c32a2ecc2f23f86519a1ec25d";
const D_S_HEX: &str = "00c1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f";

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

fn arr64(s: &str) -> [u8; 64] {
    let mut a = [0u8; 64];
    a.copy_from_slice(&unhex(s)[1..]);
    a
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// 1) userID / ENTL / ZA：与 GmSSL `sm2_compute_z`（默认 ID）逐字节相同。
///    这条同时证明 `ENTL` 是大端 `00 80`（写成 `80 00` 会立刻不同）。
#[test]
fn za_matches_gmssl_with_default_id() {
    let pub64 = arr64(PB_S_HEX);
    // GmSSL 3.1.1: sm2_compute_z(pub, SM2_DEFAULT_ID) 的输出
    assert_eq!(
        hex(&sm2::z_a(&pub64, sm2::DEFAULT_ID)),
        "feb6483dfe16f70dc0f8f732b286c606a4c432cf093d2445ecdea3c19da4b75b"
    );
    assert_eq!(sm2::DEFAULT_ID, b"1234567812345678");
    assert_eq!(sm2::DEFAULT_ID.len() * 8, 0x0080);
}

/// 2) `ZA` 在内部参与：`e = SM3(ZA ‖ msg)`；msg 里**不含** ZA。
#[test]
fn za_is_internal_not_part_of_message() {
    let pub64 = arr64(PB_S_HEX);
    let msg = b"YSAUTH1\x01....";
    let e1 = sm2::message_digest(&pub64, msg, sm2::DEFAULT_ID);
    let mut za_and_msg = sm2::z_a(&pub64, sm2::DEFAULT_ID).to_vec();
    za_and_msg.extend_from_slice(msg);
    assert_eq!(e1, sm3(&za_and_msg), "e 必须是 SM3(ZA‖msg)");

    // 若把 ZA 拼进 msg 再算，会得到不同结果（说明实现没有混进去）
    let mut msg_with_za = sm2::z_a(&pub64, sm2::DEFAULT_ID).to_vec();
    msg_with_za.extend_from_slice(msg);
    assert_ne!(
        e1,
        sm2::message_digest(&pub64, &msg_with_za, sm2::DEFAULT_ID)
    );
}

/// 3) 两条域前缀不混用：包签名是 `YSSIG1`，认证挑战是 `YSAUTH1`。
#[test]
fn domain_prefixes_are_distinct() {
    assert_eq!(v1::SIG_PREFIX, *b"YSSIG1");
    assert_ne!(&v1::SIG_PREFIX[..], &b"YSAUTH1"[..]);

    let sk: [u8; 32] = {
        let mut a = [0u8; 32];
        a.copy_from_slice(&unhex(D_S_HEX));
        a
    };
    let pub64 = arr64(PB_S_HEX);
    let k = U256::from_be_bytes(&[0x11; 32]);
    let mut auth_msg = b"YSAUTH1".to_vec();
    auth_msg.extend_from_slice(b"payload");
    let mut pack_msg = b"YSSIG1".to_vec();
    pack_msg.extend_from_slice(b"payload");

    let sig_auth = sm2::sign_with_k(&sk, &auth_msg, sm2::DEFAULT_ID, &k)
        .unwrap()
        .unwrap();
    let sig_pack = sm2::sign_with_k(&sk, &pack_msg, sm2::DEFAULT_ID, &k)
        .unwrap()
        .unwrap();
    assert_ne!(sig_auth, sig_pack);
    assert!(sm2::verify(&pub64, &auth_msg, sm2::DEFAULT_ID, &sig_auth).unwrap());
    assert!(!sm2::verify(&pub64, &pack_msg, sm2::DEFAULT_ID, &sig_auth).unwrap());
}

/// 4) `xA/yA` 取**签名者**公钥：用发送方私钥签，只有发送方公钥能验过。
#[test]
fn za_uses_signer_public_key() {
    let sk: [u8; 32] = {
        let mut a = [0u8; 32];
        a.copy_from_slice(&unhex(D_S_HEX));
        a
    };
    let signer_pub = sm2::public_from_private(&sk).unwrap();
    let other = sm2::public_from_private(&[0x22; 32]).unwrap();
    let msg = b"YSAUTH1\x01nonce...";
    let k = U256::from_be_bytes(&[0x33; 32]);
    let raw = sm2::sign_with_k(&sk, msg, sm2::DEFAULT_ID, &k)
        .unwrap()
        .unwrap();
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&raw);

    assert!(sm2::verify(&signer_pub, msg, sm2::DEFAULT_ID, &sig).unwrap());
    assert!(!sm2::verify(&other, msg, sm2::DEFAULT_ID, &sig).unwrap());

    assert_ne!(
        sm2::message_digest(&signer_pub, msg, sm2::DEFAULT_ID),
        sm2::message_digest(&other, msg, sm2::DEFAULT_ID)
    );
    // 签名者公钥就是私钥派生出来的那把
    assert_eq!(hex(&signer_pub), PB_S_HEX[2..]);
}
