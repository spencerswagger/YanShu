//! 宿主侧命令行工具，供 `scripts/crosscheck/crosscheck.py` 做反向验证
//! （GmSSL 生成 → 本实现验收），也可手工排查。
//!
//! ```text
//! ys-tool sm3 <hex>
//! ys-tool sm2-decrypt <priv-hex> <ciphertext-hex>      # 接受带/不带 0x04 前缀
//! ys-tool sm2-verify <pub65-hex> <msg-hex> <der-sig-hex>
//! ys-tool sm2-verify-raw <pub64-hex> <msg-hex> <r||s-hex>
//! ys-tool gcm-enc <key-hex> <nonce-hex> <aad-hex> <pt-hex>
//! ys-tool gcm-dec <key-hex> <nonce-hex> <aad-hex> <ct-hex> <tag-hex>
//! ys-tool pack-meta <pack-hex> <recipient-priv-hex> [expected-sender-code]
//! ys-tool pack-unpack <pack-hex> <recipient-priv-hex> [expected-sender-code]
//! ys-tool user-code <pub65-hex>
//! ys-tool check-symbol <pub65-hex>
//! ```

use std::process::exit;

use yanshu_sm::{code, der, gcm, pack, sm2, sm3};

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

fn fixed<const N: usize>(s: &str) -> [u8; N] {
    let v = unhex(s);
    if v.len() != N {
        fail(&format!("expected {}-byte value", N));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    out
}

fn fail(msg: &str) -> ! {
    eprintln!("ys-tool: {}", msg);
    exit(2);
}

fn raw_sig_from_der(der_bytes: &[u8]) -> [u8; 64] {
    let (r, s) = der::decode_signature(der_bytes).unwrap_or_else(|_| fail("bad DER signature"));
    let mut raw = [0u8; 64];
    raw[..32].copy_from_slice(&r);
    raw[32..].copy_from_slice(&s);
    raw
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        fail("subcommand required");
    }
    match args[1].as_str() {
        "sm3" => {
            println!("{}", hex(&sm3::sm3(&unhex(&args[2]))));
        }
        "sm2-decrypt" => {
            let sk = fixed::<32>(&args[2]);
            let ct = unhex(&args[3]);
            // 契约里 C1 带 0x04；测试向量里是原始 C1C3C2（不带前缀）
            let body = if ct.len() >= 98 && ct[0] == 0x04 {
                &ct[1..]
            } else {
                &ct[..]
            };
            match sm2::decrypt(&sk, body) {
                Ok(pt) => println!("{}", hex(&pt)),
                Err(e) => {
                    println!("ERR {}", e.name());
                    exit(1);
                }
            }
        }
        "sm2-verify" => {
            let pub65 = fixed::<65>(&args[2]);
            if pub65[0] != 0x04 {
                fail("pubkey must start with 0x04");
            }
            let pub64: [u8; 64] = pub65[1..].try_into().expect("64");
            let msg = unhex(&args[3]);
            let sig = raw_sig_from_der(&unhex(&args[4]));
            match sm2::verify(&pub64, &msg, sm2::DEFAULT_ID, &sig) {
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
        "sm2-verify-raw" => {
            let pub64 = fixed::<64>(&args[2]);
            let msg = unhex(&args[3]);
            let sig = fixed::<64>(&args[4]);
            match sm2::verify(&pub64, &msg, sm2::DEFAULT_ID, &sig) {
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
            let key = fixed::<16>(&args[2]);
            let nonce = unhex(&args[3]);
            let aad = unhex(&args[4]);
            let pt = unhex(&args[5]);
            let mut ct = vec![0u8; pt.len()];
            let mut tag = [0u8; 16];
            gcm::encrypt(&key, &nonce, &aad, &pt, &mut ct, &mut tag);
            println!("{}{}", hex(&ct), hex(&tag));
        }
        "gcm-dec" => {
            let key = fixed::<16>(&args[2]);
            let nonce = unhex(&args[3]);
            let aad = unhex(&args[4]);
            let ct = unhex(&args[5]);
            let tag = fixed::<16>(&args[6]);
            match gcm::decrypt(&key, &nonce, &aad, &ct, &tag) {
                Some(pt) => println!("{}", hex(&pt)),
                None => {
                    println!("FAIL");
                    exit(1);
                }
            }
        }
        "pack-meta" => {
            let p = unhex(&args[2]);
            let sk = fixed::<32>(&args[3]);
            match pack::open_only(&p, &sk) {
                Ok(opened) => {
                    let header = &opened.header;
                    let m = &opened.manifest;
                    let sender_pub = &opened.sender_public;
                    let sender_code = &opened.sender_code;
                    println!(
                        "{{\"version\":\"{}\",\"name\":\"{}\",\"mime\":\"{}\",\"ext\":\"{}\",\"size\":{},\"chunk_size\":{},\"chunk_count\":{},\"created_at_ms\":{},\"sender_code\":\"{}\",\"sender_pub\":\"{}\",\"kdf_salt\":\"{}\"}}",
                        pack::v1::VERSION_STRING,
                        m.name,
                        m.mime,
                        m.ext,
                        m.file_size,
                        m.chunk_size,
                        m.chunk_count,
                        m.created_at_ms,
                        sender_code,
                        hex(sender_pub),
                        hex(&header.kdf_salt)
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
            let sk = fixed::<32>(&args[3]);
            let expected = args.get(4).map(|s| s.as_str());
            let result = match expected {
                Some(code) => pack::unpack_with_code(&p, &sk, code),
                None => pack::unpack(&p, &sk, None),
            };
            match result {
                Ok(u) => println!("{}", hex(&u.data)),
                Err(e) => {
                    println!("ERR {}", e.name());
                    exit(1);
                }
            }
        }
        "user-code" => {
            let pub65 = fixed::<65>(&args[2]);
            println!("{}", code::from_public_key(&pub65));
        }
        "check-symbol" => {
            let pub65 = fixed::<65>(&args[2]);
            println!("{}", code::check_symbol(&pub65));
        }
        other => fail(&format!("unknown subcommand {}", other)),
    }
}
