# prelude-only 元数据语义验收（"能看，但必须标明未校验"）

- 日期：2026-11-02
- **冻结 head（正式）**：`feat/endcrypto-wasm@**031e95b**`（本份即在该提交上构建）（wasm **127,313B**，sha256
  `c1b87d0ad9a847fa04e2f4517e3a10c2150de008772f8b985dcc1f0cfc97259f`，`ys_version()=0x00010000`）
- 与冻结 head `80400ec` 是**同一份产物**（sha256 相同），本项无需在旧 head 重跑
- 脚本：`qa/evidence/check_prelude_meta.py`（PASS/FAIL + 退出码）
- 结论：**6/6 通过**

## 为什么验这条

契约 §4.3 的 prelude = `HEADER‖SENDER_PUB‖WRAPPED_KEY‖MANIFEST_SEC‖SIG_SEC`，
清单与来源签名都在里面，所以**块没到齐也能显示"谁发的、多大、什么名字"**。
风险是"看起来成功、其实完整性没验"这种模糊态——所以必须同时验两件事：
**能读**，且**读的时候明确说"数据未校验"**。

## 结果

| 检查 | 结果 | 实测 |
|---|---|---|
| prelude-only 能解元信息 | PASS | `scope=prelude`、`data_verified=false`、`name=prelude-probe.txt`、`size=1606`、`chunk_count=2`、`sender_code=FVZ6` |
| prelude 元信息 == 整包元信息 | PASS | `name/mime/ext/size/chunk_size/chunk_count/sender_code` 逐字段一致；整包 `scope=full` |
| prelude-only 喂 `ys_unpack_meta_v1` | PASS（必须拒绝） | `ERR CRYPTO_TRUNCATED` |
| prelude-only 喂 7 参 `ys_unpack_meta` | PASS（必须拒绝） | `ERR CRYPTO_TRUNCATED` |
| 篡改 `SENDER_PUB[0]` 后 `_prelude` | PASS（必须失败） | `ERR CRYPTO_CURVE_INVALID`（来源自证不通过） |
| 篡改 `MANIFEST_SEC[0]` 后 `_prelude` | PASS（必须失败） | `ERR CRYPTO_MANIFEST_AUTH_FAILED` |

最后两条是关键：它证明 `data_verified=false` 指的是**块摘要 / 块 AEAD 未验**，
而不是"整包什么都没验"——头、来源签名、清单都真的验了。

## 复跑

```sh
python3 qa/evidence/check_prelude_meta.py --wasm <yanshu_sm.wasm> \
    [--yspk <包> --recipient-sk <私钥>] [--json-out out.json]
```

不带 `--yspk` 时用内核现打一个 2 块包（含 prelude 全部段），避免依赖外部样本。
已并入常规项：`qa/evidence/check_all.sh` 第 3 步（构建 → 两个自测 → 用户码一致性 →
**prelude-only 元数据** → 证据二生产路径）。

## 边界

- 这是**元数据语义**验收，不覆盖"块到齐后整包解出明文"（那由证据二与端到端冒烟覆盖）。
- 篡改用例只动 1 字节，覆盖"来源段 / 清单段"两个位置；未做块的逐块摘要联动（属证据二矩阵）。
