package httpapi

// 契约 §1.7.4「判定顺序写死（四类）」的**可执行门禁**。
//
// 为什么单独一个文件：`/v1/transfers/{id}/{status,prelude,chunks,complete}` 四条上传路径都走
// `requireUploadToken`，而这条规则的表述是**否定式**的——"终结态一律 410，不返回任何 401"。
// 否定式规则最容易被"先看凭据、后看状态"的实现悄悄顶掉：正常流转的用例永远看不到它
// （凭据总是有效的），只有"终结态 + 坏凭据/无凭据"这种组合才会露出来。
// 常驻检查 `check_contract_impl_parity.py` 只比错误名不跑行为，所以它当年是绿的。

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/spec"
)

// uploadPath 描述一条上传侧路径怎么打（返回响应）。
type uploadPath struct {
	name string
	hit  func(e *env, tr spec.CreateTransferResponse, token string, f fixture) apiResp
}

func uploadPaths() []uploadPath {
	return []uploadPath{
		{"status", func(e *env, tr spec.CreateTransferResponse, token string, _ fixture) apiResp {
			return e.do(http.MethodGet, spec.StatusPath(tr.TransferID), nil,
				map[string]string{spec.HeaderUploadToken: token})
		}},
		{"PUT prelude", func(e *env, tr spec.CreateTransferResponse, token string, f fixture) apiResp {
			return e.putPrelude(token, tr, f.Prelude)
		}},
		{"PUT chunk", func(e *env, tr spec.CreateTransferResponse, token string, f fixture) apiResp {
			return e.putChunk(token, tr, 0, f.Chunks[0])
		}},
		{"POST complete", func(e *env, tr spec.CreateTransferResponse, token string, _ fixture) apiResp {
			return e.do(http.MethodPost, spec.CompletePath(tr.TransferID), nil,
				map[string]string{spec.HeaderUploadToken: token})
		}},
	}
}

// terminalCase 造出一条处于某终态的传输，并给出该终态应有的码。
type terminalCase struct {
	state string
	code  spec.ErrorCode
	make  func(e *env, f fixture) spec.CreateTransferResponse
}

// TestTerminalStatePrecedesCredentials 是 §1.7.4 的门禁本体。
//
// 断言（三种凭据 × 四条路径 × 三种终态）：
//   - HTTP 状态必须是 410，`code` 必须是该终态对应的码；
//   - **不得出现任何 401**（`AUTH_MISSING` / `AUTH_TOKEN_INVALID` 都不行）——
//     契约原文："即使凭据同时不存在 / 已被轮换 / 已超期"。
func TestTerminalStatePrecedesCredentials(t *testing.T) {
	cases := []terminalCase{
		{"CONSUMED", spec.ErrTransferConsumed, func(e *env, f fixture) spec.CreateTransferResponse {
			sender, _ := e.register("发送方")
			recipient, _ := e.register("接收方")
			tr := e.readyTransfer(sender, recipient, f)
			dl := e.openLease(tr.TransferID)
			if resp := e.do(http.MethodPost, spec.AckPath(tr.TransferID), nil, e.ackHeaders(recipient, dl)); resp.status != http.StatusOK {
				t.Fatalf("ack: %d %s", resp.status, resp.body)
			}
			return tr
		}},
		{"REVOKED", spec.ErrTransferRevoked, func(e *env, f fixture) spec.CreateTransferResponse {
			sender, _ := e.register("发送方")
			recipient, _ := e.register("接收方")
			tr := e.readyTransfer(sender, recipient, f)
			if resp := e.do(http.MethodPost, spec.RevokePath(tr.TransferID), nil,
				e.authHeaders(spec.PurposeTransferRevoke, sender)); resp.status != http.StatusOK {
				t.Fatalf("revoke: %d %s", resp.status, resp.body)
			}
			return tr
		}},
		{"EXPIRED", spec.ErrTransferExpired, func(e *env, f fixture) spec.CreateTransferResponse {
			sender, _ := e.register("发送方")
			recipient, _ := e.register("接收方")
			tr := e.readyTransfer(sender, recipient, f)
			// TTL 在接口上被夹到 [3600, 86400]，造"已到期"只能把服务端时钟推过 expires_at。
			e.advance(25 * time.Hour)
			return tr
		}},
	}

	credentials := []struct {
		name  string
		token func(tr spec.CreateTransferResponse) string
	}{
		{"无凭据", func(spec.CreateTransferResponse) string { return "" }},
		{"伪造凭据", func(spec.CreateTransferResponse) string { return "not-a-real-token" }},
		{"有效凭据", func(tr spec.CreateTransferResponse) string { return tr.UploadToken }},
	}

	for _, tc := range cases {
		t.Run(tc.state, func(t *testing.T) {
			for _, path := range uploadPaths() {
				for _, cred := range credentials {
					t.Run(path.name+"/"+cred.name, func(t *testing.T) {
						e := newEnv(t, "")
						f := newFixture()
						tr := tc.make(e, f)

						resp := path.hit(e, tr, cred.token(tr), f)
						if resp.status != http.StatusGone {
							t.Fatalf("§1.7.4 被违反：%s 在 %s 终态（%s）应回 410，实测 %d %s",
								path.name, tc.state, cred.name, resp.status, resp.body)
						}
						var body struct {
							Error struct {
								Code string `json:"code"`
							} `json:"error"`
						}
						if err := json.Unmarshal(resp.body, &body); err != nil {
							t.Fatalf("解错误体: %v (%s)", err, resp.body)
						}
						if body.Error.Code != string(tc.code) {
							t.Fatalf("§1.7.4 被违反：%s 在 %s 终态应回 %s，实测 %q",
								path.name, tc.state, tc.code, body.Error.Code)
						}
					})
				}
			}
		})
	}
}

// TestNonTerminalStillChecksCredentials 是上一条的**阴性对照**：
// 未终结的传输必须照旧按凭据分支（缺 → AUTH_MISSING，错 → AUTH_TOKEN_INVALID），
// 否则"一律 410"会把真正该走 401 的场景也吞掉，门禁就变成"永远绿"。
func TestNonTerminalStillChecksCredentials(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("发送方")
	recipient, _ := e.register("接收方")
	f := newFixture()
	tr := e.readyTransfer(sender, recipient, f) // READY，未终结

	resp := e.do(http.MethodGet, spec.StatusPath(tr.TransferID), nil, nil)
	e.wantError(resp, spec.ErrAuthMissing)

	resp = e.do(http.MethodGet, spec.StatusPath(tr.TransferID), nil,
		map[string]string{spec.HeaderUploadToken: "not-a-real-token"})
	e.wantError(resp, spec.ErrAuthTokenInvalid)

	// 有效凭据要能正常看进度（证明上面两条不是因为路径坏了）。
	resp = e.do(http.MethodGet, spec.StatusPath(tr.TransferID), nil,
		map[string]string{spec.HeaderUploadToken: tr.UploadToken})
	if resp.status != http.StatusOK {
		t.Fatalf("status(有效凭据): %d %s", resp.status, resp.body)
	}
}
