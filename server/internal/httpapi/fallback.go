package httpapi

import (
	"net/http"
	"sort"
	"strings"

	"github.com/spencerswagger/YanShu/server/internal/spec"
)

// unrouted 兜住"没被任何 handler 接住"的请求（ADR-0003）。
//
// 为什么需要它：契约 §0.2 写死"**所有**非 2xx 响应统一[错误信封]"，§10 又要求
// "客户端必须按 `code` 分支"。而 `http.ServeMux` 在两种情况下自己抢答：
//
//	路径不存在   → 404 `404 page not found`（text/plain）
//	方法不被允许 → 405 `Method Not Allowed`（text/plain）
//
// 这两种响应没有 `error.code`、没有 `request_id`，客户端只能落到"请求失败（undefined）"，
// 拿不到任何可分支的信号——等于 §0.2 这条规则在运行时**没有执行**。
//
// 判定"路径存在但方法不对"用的是**第二个 mux**（只注册路径、不注册方法）：把同一批
// 路由模板按路径挂一遍，方法无关，于是 `Handler(r)` 能原样复用 Go 的模板匹配，
// 不必在这里手搓 `{code}` / `{transferId}` 的通配逻辑（手搓就会与真实路由分叉）。
type unrouted struct {
	// pathOnly 只注册了路径（方法无关），用于判断"路径本身是否存在"。
	pathOnly *http.ServeMux
	// methods 记录每个路径模板允许的方法，用来回 `Allow` 头。
	methods map[string][]string
}

// newUnrouted 由路由表构造兜底判定器。
func newUnrouted(routes []routeEntry) *unrouted {
	u := &unrouted{pathOnly: http.NewServeMux(), methods: make(map[string][]string)}
	for _, rt := range routes {
		if _, seen := u.methods[rt.pattern]; !seen {
			u.pathOnly.HandleFunc(rt.pattern, func(http.ResponseWriter, *http.Request) {})
		}
		u.methods[rt.pattern] = append(u.methods[rt.pattern], rt.method)
	}
	for pat, methods := range u.methods {
		// 有 GET 就必然有 HEAD：`ServeMux` 把 HEAD 也交给 GET handler，
		// 所以 `Allow` 里漏掉 HEAD 会让按 §10.1「改用 Allow 里的方法」的客户端少一条合法选项。
		for _, m := range methods {
			if m == http.MethodGet {
				methods = append(methods, http.MethodHead)
				break
			}
		}
		u.methods[pat] = dedupSort(methods)
	}
	return u
}

// handler 返回兜底 handler：路径存在 → 405 + Allow，否则 404。
func (u *unrouted) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, pattern := u.pathOnly.Handler(r); pattern != "" {
			if methods, ok := u.methods[pattern]; ok {
				w.Header().Set("Allow", strings.Join(methods, ", "))
			}
			fail(w, r, spec.ErrMethodNotAllowed)
			return
		}
		fail(w, r, spec.ErrRouteNotFound)
	}
}

// dedupSort 去重并排序（Allow 头要求稳定输出）。
func dedupSort(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// routeEntry 是一条"方法 + 路径模板 + handler"的路由（契约 §3 接口总表的一行）。
type routeEntry struct {
	method  string
	pattern string
	handler http.HandlerFunc
}

// key 是注册到 ServeMux 的 "METHOD /path" 形式。
func (r routeEntry) key() string { return r.method + " " + r.pattern }
