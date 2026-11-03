package httpapi

// 吊销的"复活"风险：KID 递增后为同一 transfer_id 重新签发，旧凭据字符串会不会被重新接受？
//
// 结论：KID **进了派生**，所以 T1 != T2；即便行里的哈希被重签发覆盖，T1 也过不了值闸。

import (
	"context"
	"testing"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/auth"
	"github.com/spencerswagger/YanShu/server/internal/spec"
)

func TestStaleTokenCannotBeReincarnated(t *testing.T) {
	e := newEnv(t, "")
	sender, _ := e.register("sender")
	recipient, _ := e.register("recipient")
	f := newFixture()
	tr := e.createTransfer(sender, recipient, f, nil) // KID=1 下签发 T1
	T1 := tr.UploadToken

	issuer, err := auth.NewTokenIssuer(e.cfg.TokenSecret)
	if err != nil {
		t.Fatal(err)
	}
	// 同一 transfer_id、KID=2 的派生值（即"重签发"会得到的字符串）。
	T2, err := issuer.UploadToken(tr.TransferID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if T1 == T2 {
		t.Fatal("T1 == T2：KID 没进派生，递增 KID 无法区分新旧凭据 —— 必须把 KID 拼进派生输入")
	}

	// 递增到 KID=2。
	if _, err := e.st.Pool().Exec(context.Background(),
		`UPDATE token_kid_state SET kid = 2 WHERE id = true`); err != nil {
		t.Fatal(err)
	}

	// ③ 旧 token 立刻 401 STALE。
	e.wantError(e.do("GET", spec.StatusPath(tr.TransferID), nil, map[string]string{
		spec.HeaderUploadToken: T1,
	}), spec.ErrAuthTokenStale)

	// ④ 模拟"为同一 transfer_id 重签发"：把行里的哈希与 KID 换成 T2 的。
	if _, err := e.st.Pool().Exec(context.Background(),
		`UPDATE transfers SET upload_token_sm3 = $1, upload_token_kid = '2' WHERE transfer_id = $2`,
		auth.UploadTokenHash(T2), tr.TransferID); err != nil {
		t.Fatal(err)
	}
	if resp := e.do("GET", spec.StatusPath(tr.TransferID), nil, map[string]string{
		spec.HeaderUploadToken: T2,
	}); resp.status != 200 {
		t.Fatalf("re-issued token must work: %d %s", resp.status, resp.body)
	}

	// ⑤ 旧 token 字符串仍然不能复活：值闸不放行（401 凭据类）。
	got := e.do("GET", spec.StatusPath(tr.TransferID), nil, map[string]string{
		spec.HeaderUploadToken: T1,
	})
	if got.status == 200 {
		t.Fatal("stale token was reincarnated after re-issue")
	}
	e.wantError(got, spec.ErrAuthTokenInvalid)

	_ = time.Now
}
