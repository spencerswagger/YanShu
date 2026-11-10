# 路由级错误文案的用户可见行为验收（PR #72）

只断言用户看到的**行为**，不锁文案措辞（文案逐字由 `web/tests/error-copy.test.js` 锁）：

```sh
node qa/evidence/web/check_error_copy.mjs <web 目录>
```

| 用例 | 判据 |
|---|---|
| A. `ROUTE_NOT_FOUND` / `METHOD_NOT_ALLOWED` | 有中文文案（标题无 ASCII 字母）、不落兜底、非终结、不自动重试 |
| B. 未知码 `WAT_999` | 仍走兜底 `请求失败（WAT_999）`，hint 保留服务端 message |
| C. 老形态 `HTTP_404` | 仍走兜底，不抛不吞 |
| D. `CODE_NOT_FOUND` | 仍归自己的文案，不被新文案串味 |

A/B 对照（results/）：`*-web-copy-pre.log`（#72 之前 → 3/5 FAIL）、`*-web-copy-post.log`（main → 5/5 PASS）。
