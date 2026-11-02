//! Gate 侧独立驱动：用 `yanshu-sm` 真实实现打包 / 解包，供
//! `qa/evidence/tamper_probe.py --backend cmd` 调用。
//!
//! 这不是产品代码，只做两件事：产一个真包、解一个包（成功/失败都要给出可判定的信号）。
//! 因此它刻意不包含任何"尽力恢复"逻辑：
//!
//! * `unpack` 成功 → 写出明文，`OK <len>`，退出码 0
//! * `unpack` 失败 → **不写任何输出**，`ERR <错误名>`，退出码 1
//! * 参数/IO 错误 → `probe: <原因>`，退出码 2
//!
//! 用法：
//! ```text
//! ys_pack_probe keygen <sk-out> <pk-out>
//! ys_pack_probe pack   <in> <out> --recipient-pk <f> --sender-sk <f>
//!                      [--name N] [--mime M] [--block-size BYTES]
//! ys_pack_probe unpack <in> <out> --recipient-sk <f> --sender-pk <f>
//! ```
//!
//! 密钥文件是**裸字节**（sk 32B、pk 64B x||y），不是 hex/文本，避免被当成配置误提交。
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

fn read_exact<const N: usize>(path: &str, what: &str) -> [u8; N] {
    let bytes = fs::read(path).unwrap_or_else(|e| die(&format!("read {} ({}) : {}", what, path, e)));
    if bytes.len() != N {
        die(&format!("{} ({}) must be {} bytes, got {}", what, path, N, bytes.len()));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    out
}

fn opt_value(args: &[String], key: &str) -> Option<String> {
    args.iter().position(|a| a == key).and_then(|i| args.get(i + 1)).cloned()
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
                die("pack <in> <out> --recipient-pk <f> --sender-sk <f> [--name N] [--mime M] [--block-size N]");
            }
            let data = fs::read(&args[2]).unwrap_or_else(|e| die(&format!("read input: {}", e)));
            let out_path = &args[3];
            let pk_path = opt_value(&args, "--recipient-pk").unwrap_or_else(|| die("--recipient-pk required"));
            let sk_path = opt_value(&args, "--sender-sk").unwrap_or_else(|| die("--sender-sk required"));
            let recipient_pk: [u8; 64] = read_exact(&pk_path, "recipient-pk");
            let sender_sk: [u8; 32] = read_exact(&sk_path, "sender-sk");
            let name = opt_value(&args, "--name").unwrap_or_else(|| "probe.bin".to_string());
            let mime = opt_value(&args, "--mime").unwrap_or_else(|| "application/octet-stream".to_string());
            let block_size: u32 = opt_value(&args, "--block-size")
                .map(|s| s.parse().unwrap_or_else(|_| die("bad --block-size")))
                .unwrap_or(1 << 20);

            let input = PackInput {
                recipient_public: &recipient_pk,
                sender_private: &sender_sk,
                name: &name,
                mime: &mime,
                block_size,
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
                die("unpack <in> <out> --recipient-sk <f> --sender-pk <f>");
            }
            let sealed = fs::read(&args[2]).unwrap_or_else(|e| die(&format!("read pack: {}", e)));
            let out_path = &args[3];
            let sk_path = opt_value(&args, "--recipient-sk").unwrap_or_else(|| die("--recipient-sk required"));
            let pk_path = opt_value(&args, "--sender-pk").unwrap_or_else(|| die("--sender-pk required"));
            let recipient_sk: [u8; 32] = read_exact(&sk_path, "recipient-sk");
            let sender_pk: [u8; 64] = read_exact(&pk_path, "sender-pk");

            match pack::unpack(&sealed, &recipient_sk, &sender_pk) {
                Ok(unpacked) => {
                    fs::write(out_path, &unpacked.data)
                        .unwrap_or_else(|e| die(&format!("write plaintext: {}", e)));
                    println!("OK {} {}", unpacked.data.len(), unpacked.manifest.block_count);
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
