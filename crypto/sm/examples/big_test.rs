use yanshu_sm::bigint::U256;
use yanshu_sm::pack::{PackParams, PackStream};

fn main() {
    let recipient = [0x11u8; 64];
    // 造一把真实公钥
    let sk = [0x22u8; 32];
    let pub64 = yanshu_sm::sm2::public_from_private(&sk).unwrap();
    let _ = recipient;
    let params = PackParams {
        dk: [7u8; 32],
        kdf_salt: [9u8; 16],
        k_enc: U256::from_be_bytes(&[0x33; 32]),
        k_sig: U256::from_be_bytes(&[0x44; 32]),
    };
    for mib in [79u64, 80, 81] {
        let total = mib * 1024 * 1024;
        let chunk = 1u32 << 20;
        let mut s = PackStream::begin_with_params(
            &pub64,
            &sk,
            "big.bin",
            "application/octet-stream",
            "bin",
            1_767_225_600_000,
            chunk,
            total,
            &params,
        )
        .expect("begin");
        let buf = vec![0xABu8; chunk as usize];
        let n = (total / chunk as u64) as usize;
        for _ in 0..n {
            s.hash_update(&buf).expect("hash");
        }
        match s.make_prelude() {
            Ok(len) => println!(
                "{} MiB -> prelude {} B, chunks {}",
                mib,
                len,
                s.chunk_count()
            ),
            Err(e) => println!("{} MiB -> error {:?}", mib, e),
        }
    }
}
