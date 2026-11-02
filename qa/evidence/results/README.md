# results · 证据结果存放约定

结果**按布局分目录**存放，目录名一眼能看出是"对契约实现"还是"对非契约实现"：

```
results/
├─ contract-v1/            用契约布局（CRYPTO-PACK YSPK/1.0，默认）跑的结果 → 算验收
└─ rune-v1-noncontract/    用旧/其它布局跑的结果 → 只作记录与对照，不算验收
```

文件命名：`YYYY-MM-DD-evidence<编号>-<对象>.md`，例如
`rune-v1-noncontract/2026-11-02-evidence2-rune-v1.md`、
`contract-v1/2026-11-03-evidence2-contract-v1.md`。

规矩：

1. **同一份结论只放一个文件**，重跑就加新文件，不覆盖历史。
2. 非契约布局的结果，文件头必须写清"不作验收"以及"为什么"。
3. 反例用例的**通过判定与错误码无关**：只要解密失败（任一道防线拒绝）就算 PASS，
   错误名只作诊断记录。换实现/换布局后错误名会变，这是预期，不是回归。
4. 结果文件里**不放密钥、不放明文**：只写错误名、字节数、偏移、路径（路径不含用户内容），
   命中上下文最多左右各 8 字节 hex。
5. 每份结果都要带**可复跑命令**与对象版本（分支 + commit）。

现有结果：

| 文件 | 对象 | 状态 |
|---|---|---|
| `contract-v1/2026-11-02-evidence1-core-c3c2fc9.md` | 服务端 @ `c3c2fc9` + 契约包 | 存储/DB/日志三处零命中，3 组阳性对照全部触发 |
| `contract-v1/2026-11-02-evidence2-contract-v1.md` | 端侧 @ `de6d6e1`（契约布局，Rust 原生 API 入口） | 5/5、10/10、18/18；入口属测试入口 |
| `contract-v1/2026-11-02-evidence2-contract-v1-wasm.md` | 端侧 @ `cdcba0e`（**wasm C ABI 生产导出路径**） | 5/5、10/10、18/18；可作为 v1 验收 |
| `rune-v1-noncontract/2026-11-02-evidence2-rune-v1.md` | 端侧 `crypto/sm` @ `12b3d94`（旧布局） | 记录与对照 |
