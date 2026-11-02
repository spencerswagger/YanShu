//! 宿主侧命令行工具，供 `scripts/crosscheck/crosscheck.py` 做反向验证
//! （GmSSL 生成 → 本实现验收），也可手工排查。
//!
//! 用法：
//! ```text
//! ys-tool sm3 <hex>
//! ys-tool sm2-decrypt <priv-hex> <ciphertext-hex>
//! ys-tool sm2-verify <pub-hex> <msg-hex> <sig-hex>
//! ys-tool gcm-enc <key-hex> <nonce-hex> <aad-hex> <pt-hex>
//! ys-tool gcm-dec <key-hex> <nonce-hex> <aad-hex> <ct-hex> <tag-hex>
//! ys-tool pack-meta <pack-hex> <recipient-priv-hex> <sender-pub-hex>
//! ys-tool pack-unpack <pack-hex> <recipient-priv-hex> <sender-pub-hex>
//! ys-tool user-code <pub-hex>
//! ```

use std::process::exit;

use yanshu_sm::{code, gcm, pack, sm2, sm3};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    if s.len() % 2 != 0 {
        fail("odd hex length");
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap_or_else(|_| fail("bad hex")))
        .collect()
}

fn fixed32(s: &str) -> [u8; 32] {
    let v = unhex(s);
    if v.len() != 32 {
        fail("expected 32-byte value");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

fn fixed64(s: &str) -> [u8; 64] {
    let v = unhex(s);
    if v.len() != 64 {
        fail("expected 64-byte value");
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&v);
    out
}

fn fixed16(s: &str) -> [u8; 16] {
    let v = unhex(s);
    if v.len() != 16 {
        fail("expected 16-byte value");
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&v);
    out
}

fn fail(msg: &str) -> ! {
    eprintln!("ys-tool: {}", msg);
    exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        fail("subcommand required");
    }
    match args[1].as_str() {
        "sm3" => {
            let data = unhex(&args[2]);
            println!("{}", hex(&sm3::sm3(&data)));
        }
        "sm2-decrypt" => {
            let sk = fixed32(&args[2]);
            let ct = unhex(&args[3]);
            match sm2::decrypt(&sk, &ct) {
                Ok(pt) => println!("{}", hex(&pt)),
                Err(e) => {
                    println!("ERR {}", e.name());
                    exit(1);
                }
            }
        }
        "sm2-verify" => {
            let pk = fixed64(&args[2]);
            let msg = unhex(&args[3]);
            let sig = fixed64(&args[4]);
            match sm2::verify(&pk, &msg, sm2::DEFAULT_ID, &sig) {
                Ok(true) => println!("OK"),
                Ok(false) => {
                    println!("FAIL");
                    exit(1);
                }
                Err(e) => {
                    println!("ERR {}", e.name());
                    exit(1);
                }
            }
        }
        "gcm-enc" => {
            let k16 = fixed16(&args[2]);
            let nonce = unhex(&args[3]);
            let aad = unhex(&args[4]);
            let pt = unhex(&args[5]);
            let mut ct = vec![0u8; pt.len()];
            let mut tag = [0u8; 16];
            gcm::encrypt(&k16, &nonce, &aad, &pt, &mut ct, &mut tag);
            println!("{}{}", hex(&ct), hex(&tag));
        }
        "gcm-dec" => {
            let k16 = fixed16(&args[2]);
            let nonce = unhex(&args[3]);
            let aad = unhex(&args[4]);
            let ct = unhex(&args[5]);
            let tagv = unhex(&args[6]);
            if tagv.len() != 16 {
                fail("tag must be 16 bytes");
            }
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&tagv);
            match gcm::decrypt(&k16, &nonce, &aad, &ct, &tag) {
                Some(pt) => println!("{}", hex(&pt)),
                None => {
                    println!("FAIL");
                    exit(1);
                }
            }
        }
        "pack-meta" => {
            let p = unhex(&args[2]);
            let sk = fixed32(&args[3]);
            let pk = fixed64(&args[4]);
            match pack::open_manifest(&p, &sk, &pk) {
                Ok((header, manifest)) => {
                    println!(
                        "{{\"name\":\"{}\",\"mime\":\"{}\",\"size\":{},\"block_size\":{},\"block_count\":{},\"file_id\":\"{}\"}}",
                        manifest.name,
                        manifest.mime,
                        manifest.plain_size,
                        manifest.block_size,
                        manifest.block_count,
                        hex(&header.file_id)
                    );
                }
                Err(e) => {
                    println!("ERR {}", e.name());
                    exit(1);
                }
            }
        }
        "pack-unpack" => {
            let p = unhex(&args[2]);
            let sk = fixed32(&args[3]);
            let pk = fixed64(&args[4]);
            match pack::unpack(&p, &sk, &pk) {
                Ok(u) => println!("{}", hex(&u.data)),
                Err(e) => {
                    println!("ERR {}", e.name());
                    exit(1);
                }
            }
        }
        "user-code" => {
            let pk = fixed64(&args[2]);
            println!("{}", code::from_public_key(&pk));
        }
        other => fail(&format!("unknown subcommand {}", other)),
    }
}
