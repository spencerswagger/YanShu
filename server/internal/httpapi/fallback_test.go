package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spencerswagger/YanShu/server/internal/spec"
)

// 契约 §0.2：**所有**非 2xx 响应统一[错误信封]；§10 又要求"客户端必须按 `code` 分支"。
//
// 修前（ADR-0003 之前）这两条在运行时没执行：`http.ServeMux` 自己抢答
// `404 page not found` / `Method Not Allowed`（text/plain，无 `code`、无 `request_id`），
// 客户端拿不到任何可分支的信号。本文件把这条规则变成可执行门禁。
//
// 用例分两类，缺一不可：
//   - 违规输入必须真报错（未知路径 → 404 信封；未定义方法 → 405 信封 + Allow）；
//   - **阴性对照**：真实路由不被兜底吞掉（否则"兜底"会退化成"一律 404 也算通过"）。

// stubRoutes 用同一张路由表建 mux，但把 handler 全部换成 204：本文件只验路由与信封，
// 不碰 store/PG（无 TEST_DATABASE_URL 也能跑，属于纯路由门禁）。
func stubRoutes(a *API) ([]routeEntry, *http.ServeMux) {
	routes := a.routes()
	out := make([]routeEntry, 0, len(routes))
	mux := http.NewServeMux()
	for _, rt := range routes {
		rt.handler = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }
		out = append(out, rt)
		mux.HandleFunc(rt.key(), rt.handler)
	}
	return out, mux
}

// concretePath 把路由模板里的通配段换成具体值，用于真打请求。
func concretePath(pattern string) string {
	return strings.NewReplacer(
		"{"+spec.ParamCode+"}", "AWQW",
		"{"+spec.ParamTransferID+"}", "0123456789abcdef0123456789abcdef",
		"{"+spec.ParamIndex+"}", "0",
	).Replace(pattern)
}

func decodeErrorEnvelope(t *testing.T, rec *httptest.ResponseRecorder) spec.ErrorResponse {
	t.Helper()
	var env spec.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("响应不是合法 JSON（§0.2 信封规则被违反）：%v；body=%q", err, rec.Body.String())
	}
	return env
}

// 违规输入 1：路径不存在 → 404 + 信封（不是 `404 page not found`）。
func TestUnroutedPathKeepsContractEnvelope(t *testing.T) {
	routes, mux := stubRoutes(&API{})
	h := guardUnrouted(mux, routes)

	for _, path := range []string{"/v1/nope", "/v1/codes/AWQW/x", "/v1/transfers/x/chunks/0/extra", "/", "/favicon.ico"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: status = %d, want 404", path, rec.Code)
		}
		if ct := rec.Header().Get(spec.HeaderContentType); !strings.HasPrefix(ct, "application/json") {
			t.Fatalf("%s: Content-Type = %q, want JSON 信封（不许 text/plain）", path, ct)
		}
		if env := decodeErrorEnvelope(t, rec); env.Error.Code != string(spec.ErrRouteNotFound) {
			t.Fatalf("%s: code = %q, want %q", path, env.Error.Code, spec.ErrRouteNotFound)
		}
	}
}

// 违规输入 2：路径成立但方法不在 §3 表里 → 405 + 信封 + Allow（不是 `Method Not Allowed` 裸文本）。
func TestWrongMethodKeepsContractEnvelope(t *testing.T) {
	routes, mux := stubRoutes(&API{})
	h := guardUnrouted(mux, routes)

	cases := []struct {
		method, path string
		allow        []string
	}{
		{http.MethodDelete, spec.PathConfig, []string{http.MethodGet}},
		{http.MethodPost, spec.PathStats, []string{http.MethodGet}},
		{http.MethodGet, spec.PathTransfers, []string{http.MethodPost}},
		{http.MethodPost, concretePath(spec.PathCode), []string{http.MethodGet, http.MethodPatch}},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s: status = %d, want 405", c.method, c.path, rec.Code)
		}
		if ct := rec.Header().Get(spec.HeaderContentType); !strings.HasPrefix(ct, "application/json") {
			t.Fatalf("%s %s: Content-Type = %q, want JSON 信封", c.method, c.path, ct)
		}
		if env := decodeErrorEnvelope(t, rec); env.Error.Code != string(spec.ErrMethodNotAllowed) {
			t.Fatalf("%s %s: code = %q, want %q", c.method, c.path, env.Error.Code, spec.ErrMethodNotAllowed)
		}
		allow := rec.Header().Get("Allow")
		for _, m := range c.allow {
			if !strings.Contains(allow, m) {
				t.Fatalf("%s %s: Allow = %q, want 含 %s", c.method, c.path, allow, m)
			}
		}
	}
}

// 阴性对照：§3 表里的每一行（方法+路径）都必须照旧走到真 handler，不许被兜底抢走。
// 这条同时是"路由表漏写"的探测器：新增路由不在 routes() 里就会被这里点名。
func TestRoutedRequestsAreNotSwallowed(t *testing.T) {
	routes, mux := stubRoutes(&API{})
	h := guardUnrouted(mux, routes)

	if len(routes) < 20 {
		t.Fatalf("路由表只有 %d 条，契约 §3 是 21 行——漏注册了？", len(routes))
	}
	for _, rt := range routes {
		path := concretePath(rt.pattern)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(rt.method, path, nil))
		if rec.Code != http.StatusNoContent {
			t.Fatalf("%s %s 被兜底抢答：status = %d（body=%q）", rt.method, path, rec.Code, rec.Body.String())
		}
	}
}
