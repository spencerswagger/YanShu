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
			a.internalError(w, r, "stats today", err)
			return
		}
		totalConsumed, totalBytes, totalCreated, err := a.store.TotalStats(r.Context())
		if err != nil {
			a.internalError(w, r, "stats total", err)
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
