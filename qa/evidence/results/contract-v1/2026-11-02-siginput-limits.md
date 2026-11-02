# `SIG_INPUT` 三层限额验收（`97d156c` 产物）

- 日期：2026-11-02
- 脚本：`qa/evidence/check_siginput_limits.py`（自起实例、逐条探针、退出码）
- 对象：`feat/server-skeleton@97d156c` 自编二进制
- 结论：**4/5 PASS**；唯一 FAIL 是 **`SIG_INPUT_TOO_LONG` 未实现且当前不可达**

## 1. 长度表（契约 §1.3 vs 实测推导）

| PURPOSE | 字段串上限 | `SIG_INPUT` 最长 | 字段串构成 |
|---|---:|---:|---|
| `0x01 REGISTER` | 69 | **109** | `CODE(4)‖PUBKEY(65)` |
| `0x02 NICKNAME_UPDATE` | 38 | 78 | `CODE(4)‖u16be(2)‖NICKNAME(≤32)` |
| `0x03 TRANSFER_CREATE` | 60 | 100 | `4+4+8+4+4+4+32` |
| `0x04 TRANSFER_REVOKE` | 36 | 76 | `CODE(4)‖TRANSFER_ID(32)` |
| `0x05 INBOX_LIST` | 4 | 44 | `CODE(4)` |
| `0x06 WS_HELLO` | 4 | 44 | `CODE(4)` |
| `0x07 TRANSFER_ACK` | 36 | 76 | `CODE(4)‖TRANSFER_ID(32)` |
| `0x08 UPLOAD_TOKEN_ISSUE` | 36 | 76 | `CODE(4)‖TRANSFER_ID(32)` |

→ 合法上限 **109**，与契约一致（`40 + 69`）。契约只有 8 个 PURPOSE（含 `0x08`），
不是 7 个——`0x08` 是后加的重签发用途，也在表内。

## 2. 探针结果

| # | 场景 | 期望 | 实测 | 判定 |
|---|---|---|---|---|
| 1 | 长度表推导上限 | 109 | **109** | PASS |
| 2 | `REGISTER` 恰好 109 字节 | 接受（走到验签） | **401 `AUTH_SIGNATURE_INVALID`** | PASS |
| 3 | `REGISTER` 110 字节（PUBKEY 66） | 字段级错误、非 TOO_LONG | **400 `BAD_REQUEST`** | PASS（但错误名偏笼统） |
| 4 | 昵称 **33 字节** | `NICKNAME_INVALID` | **400 `NICKNAME_INVALID`** | PASS |
| 5 | **513 字节**输入（昵称 467） | `400 SIG_INPUT_TOO_LONG` | **400 `NICKNAME_INVALID`** | **FAIL** |

## 3. FAIL 的真实含义（两件事要分开说）

1. **`SIG_INPUT_TOO_LONG` 这个错误码在实现里不存在**：
   `grep -r "SIG_INPUT_TOO_LONG" server/` 零命中；`spec` 里也没有该常量。
2. **513 字节在 HTTP 层根本走不到**：昵称先被 `sanitizeNickname` 以 `NICKNAME_INVALID` 拒掉
   （≤32 字节），其他字段都是定长，所以"拼出 >512 的 `SIG_INPUT`"没有任何入口。
   库里确实有 `MaxSIGInputLen = 512` 的门（`verifier.go`），但超限只会返回 `ErrBadInput`（`BAD_REQUEST`），
   而且**不可达**。

按契约口径：**"MUST 用字段级错误、MUST NOT 用字节上限代替字段校验"这条实现是对的**
（3、4 两条就是证据）；缺的是"超 512 返回专属错误码"这一条，属**契约与实现的措辞差**，
且当前不可观测。建议：要么实现该码（哪怕不可达，作为将来加字段的护栏），
要么在契约里注明"512 门当前不可达、超限归 `BAD_REQUEST`"。

## 4. 复跑

```sh
python3 qa/evidence/check_siginput_limits.py --binary <yanshu-server> \
  --dsn "<DSN>&search_path=<已迁移 schema>" --kid 9 --work <含 kernel/ 的工作目录>
```
