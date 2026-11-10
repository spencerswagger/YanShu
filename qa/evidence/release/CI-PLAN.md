# 最小 CI 方案（只给方案，未实施）

现状：仓库只有 `.github/workflows/build-images.yml`（镜像构建），**没有任何 test CI**。
#56 / #57 两道门禁目前靠人跑 —— 本轮已经实测到两次"人跑也会假绿"（Owl 抓到 `cmd | tee` 取到
`tee` 的退出码；Web 抓到 `wasm:sync` 不写溯源导致断言每次 SKIP）。所以这道 CI 值得加。

## 1. 方案（一个 job，一个文件）

新文件 `.github/workflows/gates.yml`，跑四段：**构建门禁 → 两道闸 → 变异必红 → 收发冒烟**。

```yaml
name: gates
on:
  pull_request:
  push:
    branches: [main]
concurrency:
  group: gates-${{ github.ref }}
  cancel-in-progress: true
jobs:
  gates:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    services:
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_USER: yanshu
          POSTGRES_PASSWORD: pg
          POSTGRES_DB: yanshu_test
        ports: ["5432:5432"]
        options: >-
          --health-cmd "pg_isready -U yanshu"
          --health-interval 5s --health-timeout 3s --health-retries 12
    env:
      TEST_DATABASE_URL: postgres://yanshu:pg@127.0.0.1:5432/yanshu_test?sslmode=disable
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.27.x"
          cache-dependency-path: server/go.sum
      - run: sudo apt-get update -qq && sudo apt-get install -y -qq postgresql-client
      - name: 构建 / vet / gofmt
        run: |
          cd server
          go build ./...
          go vet ./...
          test -z "$(gofmt -l .)"
      - name: 门禁 #57（建索引不许挡写）
        run: |
          cd server
          go test ./internal/store -run 'TestMigrationsCreateIndexesWithoutBlockingWrites|TestNoTxMigrationHasConcurrentIndex' -v
      - name: 门禁 #56（终结态 410 先于凭据 401）
        run: |
          cd server
          go test ./internal/httpapi -run 'Terminal|NonTerminal' -v
      - name: 变异必红（证明门禁有牙）
        run: qa/evidence/release/negative_checks.sh origin/main /tmp/neg
      - name: 干净环境收发冒烟（跳过建索引，约 40s）
        run: |
          python3 qa/evidence/release/clean_env_selftest.py \
            --ref HEAD --dsn "$TEST_DATABASE_URL" --work /tmp/clean --skip-index
```

要点（都是本轮踩出来的）：

- **测试名要先核**：`go test -run` 匹配不到会**静默 exit 0**。CI 里最好再加一句
  `go test ./internal/httpapi -list 'Terminal'` 断言条数，或让 `-v` 输出里 `--- PASS` 计数 ≥ 期望值。
- **`cmd | tee` 不能用来取退出码**（会拿到 `tee` 的 0）；要落文件再 cat，或用 `bash` + `pipefail`。
- 冒烟用 `--ref HEAD`（checkout 已有 `.git`）；`--skip-index` 是因为 CI 的 2 分钟预算不值得，
  建索引那条由 #57 的单测 + 变异必红覆盖。
- PG 用 `postgres:16` 还是 17：本地是 17.11，`CREATE INDEX CONCURRENTLY` 行为一致；建议跟线上
  compose 对齐（现在是 16-alpine），要改只改一行。

## 2. 成本

| 项 | 估算 | 说明 |
|---|---|---|
| 单次运行时长 | **冷 ~3.5 min / 热 ~2 min** | 构建+vet ~60–90s；两道门禁 ~10s；变异必红 ~40s；冒烟 ~40s |
| Actions 额度 | **0 元** | 仓库是 public，标准 runner 不计分钟数 |
| 落地工时 | **约 1–2 人时** | 1 个 ~80 行 yml + 2–3 次实跑调 PG service / cache |
| 维护 | 每季度 ~15 min | Go 版本号、PG 镜像版本、两条测试名（改名时 `-list` 会红） |
| 失败噪声 | 低 | 只跑确定性用例；冒烟不起 web、不碰 P2P/浏览器 |

如果仓库以后转私有：免费额度 2,000 min/月，按团队 ~10 次 PR/天、每次 2 min ≈ 600 min/月，
仍在免费额度内。

## 3. 不推荐的做法

- **pre-push hook**：只在装了 hook 的机器上生效，且 `git push --no-verify` 直接绕过 —— 挡不住
  "报告 fail 0 但断言 SKIP"这类假绿。
- **本地 `make gate` 靠自觉**：本轮两次假绿都是"人跑了、也绿了"，问题不在没跑，而在**没人复核
  退出码**。CI 的价值是把"退出码"变成不可绕过的事实。

## 4. 落地顺序（等排期）

1. 先只加「门禁 #57 + #56 + 变异必红」三段（最小、最稳，~1.5 min），观察一周；
2. 稳定后再加收发冒烟（它要起 PG + 建库 + 起进程，是最容易 flaky 的一段）；
3. 最后再决定要不要把 `build-images.yml` 与 gates 串成 release 前置。
