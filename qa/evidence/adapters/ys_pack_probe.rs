//! Gate 侧独立驱动：用 `yanshu-sm` 真实实现打包 / 解包，供
//! `qa/evidence/tamper_probe.py --backend cmd` 调用。
//!
//! 这不是产品代码，只做两件事：产一个真包、解一个包（成功/失败都要给出可判定的信号）。
//! 因此它刻意不包含任何"尽力恢复"逻辑：
//!
//! * `unpack` 成功 → 写出明文，`OK <len> <块数>`，退出码 0
//! * `unpack` 失败 → **不写任何输出**，`ERR <错误名>`，退出码 1
//! * 参数/IO 错误 → `probe: <原因>`，退出码 2
//!
//! 用法（对应契约布局 YSPK/1.0）：
//! ```text
//! ys_pack_probe keygen <sk-out> <pk-out>
//! ys_pack_probe pack   <in> <out> --recipient-pk <f> --sender-sk <f>
//!                      [--name N] [--mime M] [--ext E] [--created-at-ms N] [--chunk-size N]
//! ys_pack_probe unpack <in> <out> --recipient-sk <f> [--expect-sender-code ABCD]
//! ```
//!
//! 密钥文件是**裸字节**（sk 32B、pk 64B `x||y`；`pack` 需要 65B `0x04||x||y`，
//! 这里按需自动补前缀），不是 hex/文本，避免被当成配置误提交。
//!
//! 构建：`./build_probe.sh <path/to/crypto/sm>`（见同目录 README.md）。

use std::env;
use std::fs;
use std::process::exit;

use yanshu_sm::pack::{self, PackInput};
use yanshu_sm::rng::OsRng;
use yanshu_sm::sm2;

fn die(msg: &str) -> ! {
    eprintln!("probe: {}", msg);
    exit(2)
}

fn opt_value(args: &[String], key: &str) -> Option<String> {
    args.iter().position(|a| a == key).and_then(|i| args.get(i + 1)).cloned()
}

fn read_bytes(path: &str, what: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| die(&format!("read {} ({}): {}", what, path, e)))
}

fn read_sk(path: &str) -> [u8; 32] {
    let v = read_bytes(path, "sk");
    if v.len() != 32 {
        die(&format!("sk ({}) must be 32 bytes, got {}", path, v.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

/// 读公钥并返回 65 字节 `0x04||X||Y`；允许输入 64 字节（自动补前缀）。
fn read_pub65(path: &str) -> [u8; 65] {
    let v = read_bytes(path, "pk");
    let mut out = [0u8; 65];
    match v.len() {
        65 => out.copy_from_slice(&v),
        64 => {
            out[0] = 0x04;
            out[1..].copy_from_slice(&v);
        }
        n => die(&format!("pk ({}) must be 64 or 65 bytes, got {}", path, n)),
    }
    out
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        die("subcommand required: keygen | pack | unpack");
    }
    match args[1].as_str() {
        "keygen" => {
            if args.len() < 4 {
                die("keygen <sk-out> <pk-out>");
            }
            let mut rng = OsRng::new();
            let kp = sm2::keygen(&mut rng);
            fs::write(&args[2], kp.private_key).unwrap_or_else(|e| die(&format!("write sk: {}", e)));
            fs::write(&args[3], kp.public_key).unwrap_or_else(|e| die(&format!("write pk: {}", e)));
            // 只报长度，不回显任何密钥字节
            println!("OK {} {}", kp.private_key.len(), kp.public_key.len());
        }
        "pack" => {
            if args.len() < 4 {
                die("pack <in> <out> --recipient-pk <f> --sender-sk <f> [--name N] [--mime M] \
                     [--ext E] [--created-at-ms N] [--chunk-size N]");
            }
            let data = read_bytes(&args[2], "input");
            let out_path = &args[3];
            let pk_path = opt_value(&args, "--recipient-pk").unwrap_or_else(|| die("--recipient-pk required"));
            let sk_path = opt_value(&args, "--sender-sk").unwrap_or_else(|| die("--sender-sk required"));
            let recipient_pk = read_pub65(&pk_path);
            let sender_sk = read_sk(&sk_path);
            let name = opt_value(&args, "--name").unwrap_or_else(|| "probe.bin".to_string());
            let mime = opt_value(&args, "--mime").unwrap_or_else(|| "application/octet-stream".to_string());
            let ext = opt_value(&args, "--ext").unwrap_or_else(|| "bin".to_string());
            let created_at_ms: u64 = opt_value(&args, "--created-at-ms")
                .map(|s| s.parse().unwrap_or_else(|_| die("bad --created-at-ms")))
                .unwrap_or(1_767_225_600_000); // 2026-01-01T00:00:00Z，固定值便于对照
            let chunk_size: u32 = opt_value(&args, "--chunk-size")
                .map(|s| s.parse().unwrap_or_else(|_| die("bad --chunk-size")))
                .unwrap_or(1 << 20);

            let input = PackInput {
                recipient_public: &recipient_pk,
                sender_private: &sender_sk,
                name: &name,
                mime: &mime,
                ext: &ext,
                created_at_ms,
                chunk_size,
                data: &data,
            };
            let mut rng = OsRng::new();
            match pack::pack(&input, &mut rng) {
                Ok(bytes) => {
                    fs::write(out_path, &bytes).unwrap_or_else(|e| die(&format!("write pack: {}", e)));
                    println!("OK {} {}", bytes.len(), data.len());
                }
                Err(e) => {
                    println!("ERR {}", e.name());
                    exit(1)
                }
            }
        }
        "unpack" => {
            if args.len() < 4 {
                die("unpack <in> <out> --recipient-sk <f> [--expect-sender-code ABCD]");
            }
            let sealed = read_bytes(&args[2], "pack");
            let out_path = &args[3];
            let sk_path = opt_value(&args, "--recipient-sk").unwrap_or_else(|| die("--recipient-sk required"));
            let recipient_sk = read_sk(&sk_path);
            let expect_code = opt_value(&args, "--expect-sender-code");

            match pack::unpack(&sealed, &recipient_sk, expect_code.as_deref()) {
                Ok(unpacked) => {
                    fs::write(out_path, &unpacked.data)
                        .unwrap_or_else(|e| die(&format!("write plaintext: {}", e)));
                    println!("OK {} {}", unpacked.data.len(), unpacked.manifest.chunk_count);
                }
                Err(e) => {
                    // 失败路径绝不落任何明文（半截也不行）
                    println!("ERR {}", e.name());
                    exit(1)
                }
            }
        }
        other => die(&format!("unknown subcommand {}", other)),
    }
}
