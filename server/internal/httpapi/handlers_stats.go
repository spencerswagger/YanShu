package httpapi

// GET /v1/stats（v5）：全平台聚合统计，匿名可读。
//
// 数据来自 stats_counters（按天一行，`ack`/建包时同事务累加），**不扫 transfers**。
// 进程内缓存 60 秒；响应头显式排除 CDN/反代缓存。

import (
	"net/http"

	"github.com/spencerswagger/YanShu/server/internal/spec"
)

func (a *API) handleStats(w http.ResponseWriter, r *http.Request) {
	if !a.validateQuery(w, r) {
		return
	}

	a.statsMu.Lock()
	resp := a.statsCache
	fresh := a.statsTTL > 0 && !a.statsAt.IsZero() && a.now().Sub(a.statsAt) < a.statsTTL
	a.statsMu.Unlock()

	if !fresh {
		now := a.now()
		todayConsumed, todayBytes, todayCreated, err := a.store.DayStats(r.Context(), now)
		if err != nil {
			a.statsUnavailable(w, r, "stats today", err)
			return
		}
		totalConsumed, totalBytes, totalCreated, err := a.store.TotalStats(r.Context())
		if err != nil {
			a.statsUnavailable(w, r, "stats total", err)
			return
		}
		resp = spec.StatsResponse{
			Today: spec.StatsBucket{
				Consumed: todayConsumed, ConsumedBytes: todayBytes, Created: todayCreated,
			},
			Total: spec.StatsBucket{
				Consumed: totalConsumed, ConsumedBytes: totalBytes, Created: totalCreated,
			},
			GeneratedAt: now.UTC().Format("2006-01-02T15:04:05Z"),
		}

		a.statsMu.Lock()
		a.statsCache = resp
		a.statsAt = now
		a.statsMu.Unlock()
	}

	// 统计必须每请求取源站结果：CDN/反代一律不要缓存。
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("CDN-Cache-Control", "no-store")
	w.Header().Set("Surrogate-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}

// statsUnavailable 是统计不可用时的对外表现：契约要求 503 SERVICE_UNAVAILABLE
// （API.md §4.6「失败」），不是 500 INTERNAL —— 统计是只读的旁路数据，
// 取不到应当让前端**静默降级隐藏区块**，而不是报成服务端内部错误。
func (a *API) statsUnavailable(w http.ResponseWriter, r *http.Request, op string, err error) {
	a.log.Error("stats unavailable", "op", op, "requestId", requestIDFrom(r), "err", err.Error())
	fail(w, r, spec.ErrServiceUnavailable)
}
