package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spencerswagger/YanShu/server/internal/config"
	"github.com/spencerswagger/YanShu/server/internal/ratelimit"
	"github.com/spencerswagger/YanShu/server/internal/spec"
)

// 契约 §0.2：**所有 4xx/5xx** 响应统一[错误信封]；§10 又要求"客户端必须按 `code` 分支"。
//
// 修前（ADR-0003 之前）这条规则在运行时没执行：`http.ServeMux` 自己抢答
// `404 page not found` / `Method Not Allowed`（text/plain，无 `code`、无 `request_id`），
// 客户端拿不到任何可分支的信号。本文件把它变成可执行门禁。
//
// 四类用例，缺一不可（前三类是"违规必须报错"，第四类是"门禁自己不许假绿"）：
//  1. 未知路径 → 404 信封；
//  2. 方法不在 §3 表内 → 405 信封 + `Allow`（含 HEAD）；
//  3. **接线**：走 `(*API).Handler()` 真链路，证明兜底真的挂在生产链路上；
//  4. **逐行**：`routes()` 与 `docs/API.md` §3 接口总表逐行比对 + 真路由不许被吞。

// stubRoutes 用同一张路由表建 mux，但把 handler 全部换成 204：只验路由与信封，
// 不碰 store/PG。
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

	paths := []string{
		"/v1/nope",
		"/v1/codes/AWQW/x",
		"/v1/transfers/x/chunks/0/extra",
		"/", "/favicon.ico",
		"/v1/config/", // 尾斜杠不是本服务的路由写法
	}
	for _, path := range paths {
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

// 违规输入 2：路径成立但方法不在 §3 表里 → 405 + 信封 + Allow（不是裸文本）。
func TestWrongMethodKeepsContractEnvelope(t *testing.T) {
	routes, mux := stubRoutes(&API{})
	h := guardUnrouted(mux, routes)

	cases := []struct {
		method, path string
		allow        []string
	}{
		{http.MethodDelete, spec.PathConfig, []string{http.MethodGet, http.MethodHead}},
		{http.MethodPost, spec.PathStats, []string{http.MethodGet, http.MethodHead}},
		{http.MethodGet, spec.PathTransfers, []string{http.MethodPost}},
		{http.MethodPost, concretePath(spec.PathCode), []string{http.MethodGet, http.MethodPatch}},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(c.method, c.path, nil)
		h.ServeHTTP(rec, req)

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
		// 405 必须把路由模板写回请求：否则审计行只能记 "unmatched"，
		// "方法用错"在审计里彻底消失（契约 §2.1：审计只记路由模板）。
		if pattern := req.Pattern; pattern == "" || pattern == "unmatched" {
			t.Fatalf("%s %s: r.Pattern = %q, want 路由模板（审计要记模板）", c.method, c.path, pattern)
		}
	}
}

// 接线：必须走 `(*API).Handler()` 真链路，证明兜底挂在生产链路上（而不是只在测试里被直接调用）。
//
// 这一条是"把 Handler() 里的 guardUnrouted 换回裸 mux"的探测器：那样改这里会红。
// 用不带 store 的 API（纯路由，不落审计行），因此不需要 PG。
func TestHandlerWiresUnroutedFallback(t *testing.T) {
	a := New(testConfig(), nil, nil, nil, nil,
		ratelimit.NewMemory(), ratelimit.NewMemoryLockout(), nil)
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)

	get := func(method, path string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(method, srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}

	resp := get(http.MethodGet, "/v1/nope")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /v1/nope: status = %d, want 404", resp.StatusCode)
	}
	if ct := resp.Header.Get(spec.HeaderContentType); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("GET /v1/nope: Content-Type = %q, want JSON 信封（Handler 没挂兜底？）", ct)
	}
	var env spec.ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("GET /v1/nope: 不是合法 JSON：%v", err)
	}
	if env.Error.Code != string(spec.ErrRouteNotFound) {
		t.Fatalf("GET /v1/nope: code = %q, want %q", env.Error.Code, spec.ErrRouteNotFound)
	}
	// §0.2 的另一半：request_id 必须存在（证明经过中间件，不是裸 ServeMux 抢答）。
	if env.Error.RequestID == "" {
		t.Fatalf("GET /v1/nope: request_id 为空，§0.2 只满足一半")
	}

	resp405 := get(http.MethodDelete, spec.PathConfig)
	if resp405.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE /v1/config: status = %d, want 405", resp405.StatusCode)
	}
	if env405 := decode(resp405); env405.Error.Code != string(spec.ErrMethodNotAllowed) {
		t.Fatalf("DELETE /v1/config: code = %q, want %q", env405.Error.Code, spec.ErrMethodNotAllowed)
	}
}

func decode(resp *http.Response) spec.ErrorResponse {
	var env spec.ErrorResponse
	_ = json.NewDecoder(resp.Body).Decode(&env)
	return env
}

// 3xx 不在 §0.2 的覆盖内（路径规范化重定向由 net/http 自己处理）：锁住这个行为，
// 免得哪天 guard 把 307 也换成 404/信封，把客户端重定向链路打断。
func TestPathCleanRedirectIsLeftAlone(t *testing.T) {
	routes, mux := stubRoutes(&API{})
	h := guardUnrouted(mux, routes)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "//v1/config", nil))
	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("GET //v1/config: status = %d, want 307（重定向不许被兜底改写成 404）", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != spec.PathConfig {
		t.Fatalf("Location = %q, want %q", loc, spec.PathConfig)
	}
}

// HEAD 也必须被当作已路由（ServeMux 把 HEAD 交给 GET handler）：
// 否则 `Allow` 与实际可达方法不一致，客户端按 §10.1 改用 Allow 里的方法会失败。
func TestHeadIsRoutedWhereGetIs(t *testing.T) {
	routes, mux := stubRoutes(&API{})
	h := guardUnrouted(mux, routes)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, spec.PathConfig, nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("HEAD /v1/config: status = %d, want 走到 handler（204）", rec.Code)
	}
}

// §3 接口总表 ↔ routes() 逐行比对，外加"真路由不许被兜底吞"。
//
// 这是"路由漏注册"的探测器：删掉 routes() 的任意一行，这里会点名缺哪一条
// （只数条数不够——现状 21 条 = §3 的 20 行 + /healthz，删一条正好还是 20）。
func TestRoutesMatchContractTable(t *testing.T) {
	routes, mux := stubRoutes(&API{})
	h := guardUnrouted(mux, routes)

	have := make(map[string]struct{}, len(routes))
	for _, rt := range routes {
		have[rt.method+" "+rt.pattern] = struct{}{}
	}

	want := contractTable(t)
	// 契约 §3 里"定义并实现"但运行时故意缺的行（ADR-0003 §2.3 与本 PR 描述已认领）：
	// 漏掉的必须在下面显式登记，不许用"条数下限"糊过去。
	knownMissing := map[string]string{
		"POST " + spec.PathTransfer + "/token": "§3 #18 凭据重签发（§1.7.5）尚未实现，已单独登记",
	}
	for key := range knownMissing {
		if _, ok := want[key]; !ok {
			t.Fatalf("knownMissing 里的 %q 已不在 §3 表里，登记过期", key)
		}
		if _, ok := have[key]; ok {
			t.Fatalf("%q 已在 routes() 里实现，请把它从 knownMissing 删除", key)
		}
		delete(want, key)
	}
	// /healthz 是运维探活，不在契约 §3 内。
	delete(want, "GET "+spec.PathHealthz)

	for key := range want {
		if _, ok := have[key]; !ok {
			t.Fatalf("契约 §3 有、routes() 没有：%q（会被兜底成 404）", key)
		}
	}
	for key := range have {
		if _, ok := want[key]; !ok && key != "GET "+spec.PathHealthz {
			t.Fatalf("routes() 有、契约 §3 没有：%q（提供了未定义的行为）", key)
		}
	}

	// 逐条真打：路由表里每一行都必须走到 handler，不许被兜底抢走。
	for _, rt := range routes {
		path := concretePath(rt.pattern)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(rt.method, path, nil))
		if rec.Code != http.StatusNoContent {
			t.Fatalf("%s %s 被兜底抢答：status = %d（body=%q）", rt.method, path, rec.Code, rec.Body.String())
		}
	}
}

// contractTable 从 docs/API.md §3 接口总表解析出「方法 路径」集合。
//
// 只读文档，不需要 PG——契约是唯一权威，让测试直接读它，避免"手抄一份期望值"再次分叉。
func contractTable(t *testing.T) map[string]struct{} {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "API.md"))
	if err != nil {
		t.Fatalf("读契约失败：%v", err)
	}
	text := string(raw)
	start := strings.Index(text, "## 3. 接口总表")
	if start < 0 {
		t.Fatal("契约里找不到 §3 接口总表")
	}
	section := text[start:]
	if end := strings.Index(section, "\n## 4."); end > 0 {
		section = section[:end]
	}
	// | 1 | GET | `/v1/config` | 无 | ... |
	row := regexp.MustCompile("(?m)^\\|\\s*\\d+\\s*\\|\\s*([A-Z]+)\\s*\\|\\s*`([^`]+)`")
	out := make(map[string]struct{})
	for _, m := range row.FindAllStringSubmatch(section, -1) {
		method, path := m[1], m[2]
		if method == "WS" { // §3 第 19 行写 WS，实际是 GET 升级
			method = http.MethodGet
		}
		// 契约文档用 `{id}`，spec 里的路径参数名是 `transferId`（同一物，逐字对齐时抹平）。
		path = strings.ReplaceAll(path, "{id}", "{"+spec.ParamTransferID+"}")
		out[method+" "+path] = struct{}{}
	}
	if len(out) < 20 {
		t.Fatalf("§3 只解析出 %d 行，接口总表格式变了？", len(out))
	}
	return out
}

// testConfig 是纯路由用例的最小配置（不碰 store/密钥/内核）。
func testConfig() config.Config {
	return config.Config{
		Verifier:      config.VerifierStubAllow,
		TokenSecret:   []byte("test-secret"),
		TokenEpoch:    "1",
		TokenEpochNum: 1,
		STUNURLs:      []string{"stun:stun.example:3478"},
		WSURL:         "wss://example/v1/ws",
	}
}
