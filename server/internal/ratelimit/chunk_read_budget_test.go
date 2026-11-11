package ratelimit

// 回归：单传输拉 1 GiB（1024 个 1 MiB 块）不该被"单 IP 请求数"额度打残。
//
// 背景（qa/evidence/2026-11-11_v0.2.4_compose-5.6.0）：v0.2.4 干净环境下 1 GiB 接收端
// 2273 次请求里 81 次 429，进度 107→707 块花了 446 秒（1.35 块/s），卡在 69% 没落地。
// 根因是 TransferReadPerIP=120 次/分钟（=2 块/s 硬顶）+ 客户端 429 后 5s 退避。
// 修法：chunk GET 的单 IP 额度改成按字节（TransferReadBytesPerIP，MiB 计费）。

import (
	"testing"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/spec"
)

// chunkMiB 是单块的计费字节数（MiB），与 httpapi 侧 chunkCostMiB 一致。
const chunkMiB = 1.0

// pull 模拟一个接收端顺序拉 n 块，返回用时、429 次数。
// 客户端口径同 web/src/net/client.js：429 → max(5s 退避, Retry-After)，最多 3 次。
func pull(m *Memory, now *time.Time, chunks int, ipCost float64, ipLim, trLim spec.Limit) (time.Duration, int, bool) {
	start := *now
	n429 := 0
	// 模拟真实链路的单块耗时（60 MiB/s ≈ 17ms/块）：没有这一步，"无限快"的客户端
	// 会把令牌桶的补充速度当成瓶颈，测出来的 429 次数没有物理意义。
	const wirePerChunk = 17 * time.Millisecond
	for i := 0; i < chunks; i++ {
		tries := 0
		for {
			tries++
			a := m.TakeN("readbytes:ip:1.2.3.4", ipLim, ipCost)
			b := m.Take("read:transfer:t", trLim)
			if a.Allowed && b.Allowed {
				*now = now.Add(wirePerChunk)
				break
			}
			n429++
			if tries >= 3 {
				// 真实客户端 3 次仍 429 就放弃这一块 → 整次下载失败。
				return now.Sub(start), n429, false
			}
			wait := 5 * time.Second
			if a.RetryAfter > wait {
				wait = a.RetryAfter
			}
			*now = now.Add(wait)
		}
	}
	return now.Sub(start), n429, true
}

func TestChunkReadBudgetSurvives1GiB(t *testing.T) {
	cur := time.Date(2026, 11, 11, 15, 0, 0, 0, time.UTC)
	m := NewMemory()
	m.now = func() time.Time { return cur }

	// 新口径：单 IP 按字节（1024 MiB/分钟，突发 256 MiB），单传输 1800 块/分钟。
	took, n429, ok := pull(m, &cur, 1024, chunkMiB, spec.DefaultLimits.TransferReadBytesPerIP, spec.DefaultLimits.TransferReadPerTransfer)
	if !ok {
		t.Fatalf("1 GiB 拉不完：单传输被额度打残（429=%d）", n429)
	}
	// 1 GiB 的上行实测 76s；下行不该显著慢于上行，给到 120s 上限。
	if took > 120*time.Second {
		t.Fatalf("1 GiB 用时 %s，超过 120s 上限（429=%d）", took, n429)
	}
	if n429 > 8 {
		t.Fatalf("1 GiB 触发 %d 次 429，按字节计费后不该再有持续限速", n429)
	}
	t.Logf("1 GiB(1024 块) 用时 %s，429=%d", took, n429)
}

// 不变式：单 IP 的字节额度必须 ≥ 单传输的块额度（二者都以 1 MiB 为单位），
// 否则单传输又会先撞 per-IP 这一档（= v0.2.4 的 2 MiB/s 硬顶），回归重来。
func TestPerIPByteQuotaAbovePerTransfer(t *testing.T) {
	ip := spec.DefaultLimits.TransferReadBytesPerIP.Max
	tr := spec.DefaultLimits.TransferReadPerTransfer.Max
	if ip < tr {
		t.Fatalf("per-IP 字节额度 %d MiB/min < per-transfer %d 块/min → 单传输会被 per-IP 误伤", ip, tr)
	}
	if spec.DefaultLimits.TransferReadPerTransfer.Burst < 1024 {
		t.Fatalf("per-transfer 突发 %d 块 < 1024 块：1 GiB 整包仍会在启动瞬间被限速", spec.DefaultLimits.TransferReadPerTransfer.Burst)
	}
}

// 阴性对照：旧口径（按请求数 120 次/分钟）必须**失败**，否则这条回归没守住任何东西。
func TestOldPerRequestLimitStillFails1GiB(t *testing.T) {
	cur := time.Date(2026, 11, 11, 15, 0, 0, 0, time.UTC)
	m := NewMemory()
	m.now = func() time.Time { return cur }

	old := spec.Limit{WindowSeconds: 60, Max: 120, Burst: 120}
	_, n429, ok := pull(m, &cur, 1024, 0, old, spec.DefaultLimits.TransferReadPerTransfer)
	// 顺序拉 + 3 次退避会计到失败；这里只要证明"旧口径下 429 极多/打不完"。
	if ok && n429 < 30 {
		t.Fatalf("旧口径居然只触发 %d 次 429 —— 说明模拟没复现现场，回归无效", n429)
	}
	t.Logf("旧口径：429=%d，跑完=%v", n429, ok)
}
