package httpapi

// GET /v1/stats（v5）：全平台聚合统计，匿名可读。
//
// 数据来自 stats_counters（按天一行，`ack`/建包时同事务累加），**不扫 transfers**。
// 进程内缓存 60 秒；刷新走单飞（同一个时刻只有一个请求打库，其余等它填缓存）；
// 响应头显式排除 CDN/反代缓存。

import (
	"context"
	"net/http"

	"github.com/spencerswagger/YanShu/server/internal/spec"
)

// statsSnapshot 取一份统计快照：命中缓存直接返回，否则刷新一次。
//
// 刷新时**一直持锁**：并发 miss 会排队等第一个请求填好缓存，不会各自打一遍库
// （首页 10 QPS 时，60s 过期瞬间否则就是 10 条同样的聚合查询）。
func (a *API) statsSnapshot(ctx context.Context) (spec.StatsResponse, error) {
	a.statsMu.Lock()
	defer a.statsMu.Unlock()

	now := a.now()
	if a.statsTTL > 0 && !a.statsAt.IsZero() && now.Sub(a.statsAt) < a.statsTTL {
		return a.statsCache, nil
	}

	todayConsumed, todayBytes, todayCreated, err := a.store.DayStats(ctx, now)
	if err != nil {
		return spec.StatsResponse{}, err
	}
	totalConsumed, totalBytes, totalCreated, err := a.store.TotalStats(ctx)
	if err != nil {
		return spec.StatsResponse{}, err
	}
	resp := spec.StatsResponse{
		Today: spec.StatsBucket{
			Consumed: todayConsumed, ConsumedBytes: todayBytes, Created: todayCreated,
		},
		Total: spec.StatsBucket{
			Consumed: totalConsumed, ConsumedBytes: totalBytes, Created: totalCreated,
		},
		GeneratedAt: now.UTC().Format("2006-01-02T15:04:05Z"),
	}
	a.statsCache, a.statsAt = resp, now
	return resp, nil
}

func (a *API) handleStats(w http.ResponseWriter, r *http.Request) {
	if !a.validateQuery(w, r) {
		return
	}

	resp, err := a.statsSnapshot(r.Context())
	if err != nil {
		a.statsUnavailable(w, r, "stats snapshot", err)
		return
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
