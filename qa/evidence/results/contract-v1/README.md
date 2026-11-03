# contract-v1 · 对契约实现的证据结果

这个目录放**用默认契约布局（`CRYPTO-PACK` `YSPK/1.0`）跑出来的结果**，是验收要用的那一份。

目前**还没有文件**，原因：端侧实现仍在按契约返工（HEADER 112B、`SENDER_PUB` 入包、
C1 带 `0x04`=129B、DER 签名、`u64be(index)` nonce、结构化 32B AAD、摘要取明文块）。
返工推送后按下面跑：

```sh
qa/evidence/run_evidence2_rune.sh <path-to>/crypto/sm /tmp/ys-ev2   # 脚本会显式传 rune-v1
# 契约实现就绪后改成默认布局跑（不要传 --layout，或显式 --layout contract-v1）：
python3 qa/evidence/tamper_probe.py \
    --envelope <真实包>.yspk --donor <另一个包>.yspk \
    --backend cmd --expect-plaintext <原文>.bin \
    --decrypt-cmd '<解密入口> {in} {out}'
```

产出按 `YYYY-MM-DD-evidence2-<对象>.md` 命名放本目录。

判定口径提醒：**解密失败即 PASS（任一道防线拒绝都算），错误名只作诊断**。
