# ack 终态 410 独立验收（PR #71）

不采信提交人的自证：只按契约发真 HTTP、连真 PG 查 `download_count`。

```sh
python3 qa/evidence/ack/ab_ack_terminal.py --binary <yanshu-server> --dsn "$TEST_DATABASE_URL"
```

| 用例 | 判据 |
|---|---|
| A. REVOKED | `410 TRANSFER_REVOKED`（有效/无/伪造 3 种 `download_id` 都是 410），`download_count` 不变 |
| B. EXPIRED | `410 TRANSFER_EXPIRED`（同上 3 种），`download_count` 不变 |
| C. 阴性对照 | 未终结 + 缺/伪租约 → `409 DOWNLOAD_NOT_STARTED`（不许把 409 全拍成 410） |
| D. 幂等例外（ADR-0005） | `CONSUMED` + 同一 `download_id` 重复 ack → 200，且只计一次 |

A/B 对照（results/ 里三份日志）：
- `*-ack-pre.log`：`#71` 之前（`b8fabfd`）→ **2/4 FAIL**（REVOKED 有效租约 409、无/伪租约 409；EXPIRED 无/伪 409）
- `*-ack-post.log`：`#71` 之后（main）→ **4/4 PASS**
- `*-ack-mutant.log`：把终态判定挪回 `download_id` 之后 → **2/4 FAIL**（无/伪租约又变回 409），证明用例咬得住顺序
