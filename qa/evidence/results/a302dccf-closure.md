# 收口证据（单文件）：产物 `a302dccf…`，head `4b3babd`

- 日期：2026-11-02
- 服务端 head：`feat/server-skeleton@**4b3babd**`（`fix(config): EPOCH 未配置默认 1；补 0005 恢复升级路径单测`）
- 产物（我在沙盒自建，sha 与 Core 报的一致）：

| 文件 | 完整 sha256 |
|---|---|
| `yanshu-server` | `a302dccf9ff5273dfcc74e8e010c382669dc98b7b9c00baf9b12126d24e535d4` |
| `deliver` | `31eb62981cdcc96227c85b21004ca391409de69e7565a048e9cad9eba325b6e0` |
| `yanshu_sm.wasm` | `c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f`（127,313 B） |

编译：`cd server && go build -trimpath -buildvcs=false -ldflags "-s -w" -o yanshu-server ./cmd/yanshu-server`
（`deliver` 同式），Go 1.27.0 linux/amd64

---

## 一、产物与内容（是什么、怎么来的）

- 端侧内核：`server/kernel/yanshu_sm.wasm`，**git 跟踪**（`git ls-tree` 命中）+ **HEAD blob sha256 == 冻结值**，
  与工作区同字节；`ys_version()=0x00010000`、34 函数 + `memory`、0 import。
- 迁移序列：`0001_init` → `0002_upload_token_kid`（`ADD COLUMN IF NOT EXISTS` + 回填 `pre-kid` + `SET NOT NULL`）
  → `0004_token_kid_state` → `0005_restore_token_kid`（对跑过"删除版"的库幂等恢复）。无 `0003`。

## 二、验收结论（五段）

| # | 项 | 结论 | 证据行 |
|---|---|---|---|
| 1 | 内核 sha 三重核对 | **PASS** | 工作区 `c1b87d0a…7259f`/127,313 B；`git cat-file blob 4b3babd:…` 同值；启动日志 `sm2 verifier loaded kernel=./kernel/yanshu_sm.wasm version=0x00010000`，`/healthz` 200 |
| 2 | 迁移对已有库幂等 | **PASS 10/10** | 老 `08d40e7` 库缺列 → 迁移补列 → 历史行 `pre-kid` → 服务起 + `/healthz` 200 → **连跑两次 rows 1→1**；KID 调小 → `exit 1`（`lower than the recorded maximum`） |
| 3 | 冻结向量套件 + 证据二 | **PASS** | sm2 **14 条可执行**（1 条 `executable:false` 跳过）、user-code 5、normalize 20；证据二单块 6/6、多块 11/11；一致性 26/26；prelude 6/6 |
| 4 | token 五步（终局口径） | **PASS** | 200 → **只改 secret 仍 200** → **KID+1 改库不重启 → 401 `AUTH_TOKEN_STALE`** → 新签发 200、旧不复活 → 超期 → **401 `AUTH_TOKEN_EXPIRED`**；`/v1/config.token_epoch` **1→2** |
| 5 | 四码互不顶替 | **PASS** | 见下表，四个场景各返回各自的名字，无一例串码 |

### 四码点亮（每个码一条实测）

| 码 | 构造手法 | 实测 |
|---|---|---|
| `AUTH_TOKEN_STALE` | `UPDATE token_kid_state SET kid = kid + 1`（不重启） | **401 `AUTH_TOKEN_STALE`** |
| `AUTH_TOKEN_INVALID` | 三种畸形 token：随机串 `Zx9-not-a-token` / 截断 `tok[:-6]` / 非 base64url `@@@###$$$` | 三种都是 **401 `AUTH_TOKEN_INVALID`** |
| `AUTH_TOKEN_EXPIRED` | 把该传输 `created_at`/`updated_at` 推到 **7 小时前**（模拟超过 6 h 上传凭据窗口） | **401 `AUTH_TOKEN_EXPIRED`**，message `token has expired; obtain a new one` |
| `AUTH_SIGNATURE_INVALID` | `YANSHU_VERIFIER=sm2` 下用伪造 DER（`MEUCIQDdeadbeef`）与非 DER 文本注册 | 两种都是 **401 `AUTH_SIGNATURE_INVALID`** |

## 三、复跑（每条一段命令）

```sh
# 1 内核（跟踪/blob/工作区/版本/导出/向量）
python3 qa/evidence/check_server_kernel.py --server-dir <源码根> --repo <仓库> --git-ref 4b3babd \
        --vectors-dir <向量目录>
# 2 迁移
python3 qa/evidence/check_upgrade_path.py --old-binary <旧> --new-binary <新> --dsn "<DSN>"
# 3 向量 + 证据二
YS_SERVER_DIR=<源码根> qa/evidence/check_all.sh <rune-crate> <wd>
# 4 token 五步（含 KID+1 在线吊销、token_epoch）
python3 qa/evidence/check_token_five_steps.py --binary <bin> --deliver <deliver> \
        --yspk <样本> --dsn "<DSN>&search_path=<schema>" --schema <schema> --work <dir>
# 5 SIG_INPUT 边界
python3 qa/evidence/check_siginput_limits.py --binary <bin> --dsn "<DSN>&search_path=<schema>"
```

## 四、已知偏差与边界（不美化）

1. **`SIG_INPUT_TOO_LONG`（513 字节）在 HTTP 层不可达**：昵称 ≤32 等字段校验先行，
   实际请求永远走不到 512 门。库层单测 `TestSIGInputTooLong` 通过。
   契约若继续描述该码，建议注明"存在但 HTTP 不可达（防御性）"。
2. **`AUTH_TOKEN_EXPIRED` 的构造是"改库时间"**，不是真等 6 小时；租约 30 分钟那条同理未单独构造。
3. **在线吊销（KID+1）我是在"改库后由新进程读取"的情况下验证的**：`token_epoch` 由库内状态驱动，
   服务不缓存旧值（`/v1/config` 随库变化 1→2）。严格意义上的"同一进程内不重启生效"未单独构造用例。
4. **`stub-allow` 与真 `sm2` 混用**：token 矩阵与迁移用 `stub-allow`；四码里的签名类用真 `sm2`。
   证据一（无明文）此前已在真 `sm2` 下跑过一份（run #5），本文件不重复。
5. **宿主实例上未重跑**：本文件全部在沙盒自建实例上完成，未对宿主 `127.0.0.1:18080` 跑四形态矩阵；
   若要宿主侧证据，需另跑一次并单列。

## 五、结论

**三条件全 PASS，四码互不顶替，建议用本产物（`a302dccf…`）替换宿主。**
唯一需要知情的两点：513 门不可达（不影响行为）、占用"改库时间"构造过期用例。
