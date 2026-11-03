# 宿主实例真 `sm2` 验收（`c1b87d0a` / `4eda665`）

- 日期：2026-11-02
- 宿主：`http://127.0.0.1:18080`，产物 `4eda665`（`yanshu-server` = `cc117070de08bd34f52055af48bb4e28f475bdd4f71b55f705a6420cc7e571f9`），
  `YANSHU_VERIFIER=sm2`、`YANSHU_TOKEN_EPOCH=1`，内核 `c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f`（127,313 B）
- 与前几份 `stub-allow` 证据**分开留档**：本文件全部在**真 `sm2` 宿主**上取得

## 一、四形态矩阵（用户码，wasm 侧；与宿主无关但同冻结产物）

| 入口 | `PB_S` | 另 4 组 | 校验位 |
|---|---|---|---|
| wasm 64B / wasm_wire 65B / 原生 64B / 原生 65B | 四者均 **AWQW** | 逐字符相同 | 四者均 `X` |

（`check_code_consistency.py`：26/26；本项是端侧函数级，不经过宿主服务端。）

## 二、token 六步（宿主实测，能不改宿主就只做只读那几步）

| 步 | 需要什么 | 宿主实测 |
|---|---|---|
| ① 基线可用 | 签发凭据 | 投递成功、`GET /prelude` **200**（571B） |
| ② 只换 `TOKEN_SECRET` | **需改宿主 env 并重启** | **未做**（属运维动作；交付版 `06c9f56` 上实测为 **200 不吊销**） |
| ③ EPOCH/KID +1 | **需改宿主库 `token_kid_state`** | **未做**（同上；`06c9f56` 上实测**同进程 PID 不变**即 401 `STALE`） |
| ④ 旧 token → 401 `STALE` | 需先 ③ | 未做（依赖 ③） |
| ⑤ 新签发可用 | — | 宿主上新建传输 → 投递成功（本文件 §三 两笔均 `ok:true`） |
| ⑥ 旧 token 不复活 | 需先 ④ | 未做（依赖 ③） |
| 附 KID 调小拒启动 | 需另起实例 | **未做**（宿主不可重启；`06c9f56` 上实测 `exit 1`） |
| 附 畸形 token | 只读 | **401 `AUTH_TOKEN_INVALID`**（`upload token is invalid for this transfer`） |
| 附 无 token | 只读 | 401 `AUTH_MISSING` |

**结论**：宿主上能只读验证的两条（畸形/缺失）都正确；②③④⑥ 需要改宿主 env 或库，**未做、不充数**。

## 三、生产路径端到端（宿主，真 `sm2`）

| 项 | 结果 |
|---|---|
| 源文件 | 2,506,889 B，sha256 `bb17026f83d3f13fe5d6a5e4aa5c05be73efcd0604fea0b0628d6dbf9e579dc9` |
| 打包 | 3 块（1 MiB），`.yspk` 2,507,556 B |
| 投递（`deliver --sender-sk --recipient-sk`） | **成功**，`state=LEASED`、`acked=false`、code `Q7G9`、package `dc741572…e5fb` |
| `GET /prelude` | **200**，571 B，与本地前导 **逐字节一致** |
| `GET /chunks/{0,1,2}` | **200**；1048592 / 1048592 / 409753 B，**三块与本地密文逐字节一致** |
| 解密落盘 | 用取回字节解出明文，sha256 与源文件**相同** |
| `ack` 后再取 | **410 `TRANSFER_CONSUMED`**（prelude 与 chunks 都是 410，响应体原文已记） |

## 四、`SIG_INPUT` 四条（宿主真 `sm2`）

| 用例 | 宿主实测 |
|---|---|
| 109 字节 `REGISTER` | 走到验签（伪造签名 → 401 `AUTH_SIGNATURE_INVALID`，说明长度被接受） |
| 昵称 33 字节 | **400 `NICKNAME_INVALID`**（字段级，非 TOO_LONG） |
| 513 字节（昵称 467） | **400 `NICKNAME_INVALID`** —— `SIG_INPUT_TOO_LONG` 在 HTTP 上**不可达**（昵称先被字段级拒） |
| 110 字节（PUBKEY 66） | **400 `BAD_REQUEST`**（字段级） |

## 五、结论与已知偏差

**宿主 `4eda665` 在真 `sm2` 下工作正常**：投递 / 取回 / 解密 / 逐字节一致 / ack 后 410 全部实测通过。

已知偏差（如实）：

1. **token 六步只完成 3 条只读项**：②③④⑥ 需要改宿主 `TOKEN_SECRET` 或库内 `token_kid_state`，属运维动作，**未做**；
   这些行为在交付版 `06c9f56` 上已完整实测（secret→200、KID+1 同进程 401 `STALE`、调小 `exit 1`）。
2. **`SIG_INPUT_TOO_LONG` 在 HTTP 不可达**（宿主实测同样返回 `NICKNAME_INVALID`）；码本身在库层实现并有单测。
3. **宿主仍是 `4eda665`**：`AUTH_TOKEN_EXPIRED` 未实现（grep 0 处）、只换 secret 会 401 `INVALID`（旧语义）；
   换 `06c9f56` 会失效在传 token（数据无损）。
4. 未做跨浏览器验证（本文件为 API 级；浏览器端由 Web 的证据文件覆盖）。
