//! SM4-GCM 吞吐粗测（不做极致优化，只给一个数量级）。
//!
//! ```text
//! cargo run --release --bin bench-sm4 -- [MiB]
//! ```

use std::time::Instant;

use yanshu_sm::gcm;
use yanshu_sm::sm4::{self, Sm4Key};

fn main() {
    let mib: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(16);
    let size = mib * 1024 * 1024;
    let data: Vec<u8> = (0..size).map(|i| (i * 31 + 7) as u8).collect();
    let key = [0x42u8; 16];
    let nonce = [0x17u8; 12];

    // 1) SM4-GCM 整体
    let mut ct = vec![0u8; size];
    let mut tag = [0u8; gcm::TAG_SIZE];
    let t0 = Instant::now();
    gcm::encrypt(&key, &nonce, b"bench", &data, &mut ct, &mut tag);
    let enc = t0.elapsed();

    let t1 = Instant::now();
    let back = gcm::decrypt(&key, &nonce, b"bench", &ct, &tag).expect("tag");
    let dec = t1.elapsed();
    assert_eq!(back, data);

    // 2) 纯 SM4 单块（衡量分组密码本身）
    let sm4key = Sm4Key::new(&key);
    let block = [0u8; 16];
    let rounds = 200_000usize;
    let t2 = Instant::now();
    let mut acc = 0u8;
    for _ in 0..rounds {
        acc ^= sm4key.encrypt_block(&block)[0];
    }
    let block_time = t2.elapsed();
    std::hint::black_box(acc);

    let enc_mbs = size as f64 / 1024.0 / 1024.0 / enc.as_secs_f64();
    let dec_mbs = size as f64 / 1024.0 / 1024.0 / dec.as_secs_f64();
    let blk_mbs = (rounds * 16) as f64 / 1024.0 / 1024.0 / block_time.as_secs_f64();

    println!(
        "SM4-GCM 加密: {:.2} MB/s ({} MiB in {:?})",
        enc_mbs, mib, enc
    );
    println!(
        "SM4-GCM 解密: {:.2} MB/s ({} MiB in {:?})",
        dec_mbs, mib, dec
    );
    println!("SM4-ECB 单块: {:.2} MB/s", blk_mbs);
    let _ = sm4::BLOCK_SIZE;
}
