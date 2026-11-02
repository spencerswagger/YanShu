// Command deliver 是面向验收的「一次完整投递」驱动。
//
// 它只搬运**已加密的 .yspk 包**：按 docs/CRYPTO-PACK.md 的结构切出 prelude 与块切片，
// 按 docs/API.md v1 走完 注册 → 建传输 → 传 prelude/块 → complete → 凭码查询 →
// 取 prelude/块 → ack，并把验收需要的标识打印出来。
//
// 它**不做加解密**、不解析清单、不接触私钥；包必须由端侧工具产出。
//
// 鉴权说明：签名在 `YANSHU_VERIFIER=stub-allow` 的服务端上只做形状检查，因此本工具用
// 占位签名；接真实 SM2 验签后必须换成真签名（运行时会打印提醒）。
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/spencerswagger/YanShu/server/internal/gm"
	"github.com/spencerswagger/YanShu/server/internal/packet"
	"github.com/spencerswagger/YanShu/server/internal/spec"
)

// 退出码：0 成功；1 业务失败；2 用法错误；3 服务不可达；4 服务端验签为 fail-closed。
const (
	exitOK          = 0
	exitFailure     = 1
	exitUsage       = 2
	exitUnreachable = 3
	exitFailClosed  = 4
)

type options struct {
	baseURL      string
	yspk         string
	senderCode   string
	recipient    string
	recipientPub string
	nickname     string
	noAck        bool
	blobDir      string
	dsn          string
	logPath      string
	jsonOut      string
	sm3Cmd       string
	timeout      time.Duration
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(argv []string) int {
	var opt options
	fs := flag.NewFlagSet("deliver", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&opt.baseURL, "base-url", "http://127.0.0.1:8080", "服务端地址")
	fs.StringVar(&opt.yspk, "yspk", "", "已加密的 .yspk 包路径（必填）")
	fs.StringVar(&opt.senderCode, "sender-code", "", "发送方码（默认从包内 SENDER_PUB 派生）")
	fs.StringVar(&opt.recipient, "recipient-code", "", "接收方码（默认临时生成一个）")
	fs.StringVar(&opt.recipientPub, "recipient-pubkey", "", "接收方公钥 base64url（接收方未注册时用于注册）")
	fs.StringVar(&opt.nickname, "nickname", "deliver", "临时注册的昵称")
	fs.BoolVar(&opt.noAck, "no-ack", false, "取件后不 ack（保留密文供 Gate 检索）")
	fs.StringVar(&opt.blobDir, "blob-dir", "", "服务端的 YANSHU_BLOB_DIR（用于打印/校验存储路径）")
	fs.StringVar(&opt.dsn, "dsn", "", "服务端数据库 DSN（用于打印 database/schema）")
	fs.StringVar(&opt.logPath, "log", "", "服务端日志路径（仅用于打印）")
	fs.StringVar(&opt.jsonOut, "json-out", "", "把结果写成 JSON 文件")
	fs.StringVar(&opt.sm3Cmd, "sm3-cmd", "", "外部 SM3 命令：接受 hex、输出 hex（如 'ys-tool sm3'）；缺省用内置 SM3")
	fs.DurationVar(&opt.timeout, "timeout", 60*time.Second, "单次 HTTP 超时")
	if err := fs.Parse(argv); err != nil {
		return exitUsage
	}
	if opt.yspk == "" {
		fmt.Fprintln(os.Stderr, "缺少 --yspk <包路径>")
		return exitUsage
	}

	raw, err := os.ReadFile(opt.yspk)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取包失败：%v\n", err)
		return exitFailure
	}
	env, err := packet.Parse(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "包结构不合法：%v\n", err)
		return exitFailure
	}

	senderCode := gm.DeriveCode(env.SenderPublicKey)
	if opt.senderCode != "" && opt.senderCode != senderCode {
		fmt.Fprintf(os.Stderr, "包内 SENDER_PUB 派生的码是 %s，与 --sender-code %s 不一致\n", senderCode, opt.senderCode)
		return exitFailure
	}

	cli := &client{base: strings.TrimRight(opt.baseURL, "/"), http: &http.Client{Timeout: opt.timeout}}

	if err := cli.health(); err != nil {
		fmt.Fprintf(os.Stderr, "服务端不可达（%s）：%v\n", opt.baseURL, err)
		return exitUnreachable
	}
	fmt.Fprintln(os.Stderr, "注意：本工具使用占位签名，服务端须以 YANSHU_VERIFIER=stub-allow 运行；"+
		"接入真实 SM2 验签后本工具需改用真签名。")

	// 1) 注册/复用发送方（码由包内 SENDER_PUB 派生）。
	if err := cli.register(senderCode, env.SenderPublicKey, opt.nickname+"-sender"); err != nil {
		return reportErr(err)
	}

	// 2) 解析接收方。
	recipient, err := cli.ensureRecipient(opt)
	if err != nil {
		return reportErr(err)
	}

	// 3) 建传输。
	preludeSM3, err := sm3Hex(env.Prelude, opt.sm3Cmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "计算 prelude SM3 失败：%v\n", err)
		return exitFailure
	}
	created, err := cli.createTransfer(senderCode, recipient, env, preludeSM3)
	if err != nil {
		return reportErr(err)
	}
	// 4) 传 prelude 与块。
	if err := cli.putPrelude(created.UploadToken, created.TransferID, env.Prelude); err != nil {
		return reportErr(err)
	}
	for i, chunk := range env.Chunks {
		if err := cli.putChunk(created.UploadToken, created.TransferID, i, chunk); err != nil {
			return reportErr(err)
		}
	}

	// 5) complete。
	if err := cli.complete(created.UploadToken, created.TransferID); err != nil {
		return reportErr(err)
	}

	// 6) 凭码查询（接收方看得到发送方公钥与昵称）。
	if err := cli.lookupCode(recipient); err != nil {
		return reportErr(err)
	}

	// 7) 取件：prelude 开租约，然后逐块下载并逐字节比对。
	downloadID, err := cli.downloadAll(created.TransferID, env)
	if err != nil {
		return reportErr(err)
	}

	// 8) ack（可用 --no-ack 保留密文）。
	state := "LEASED"
	acked := false
	if !opt.noAck {
		state, err = cli.ack(recipient, created.TransferID, downloadID)
		if err != nil {
			return reportErr(err)
		}
		acked = true
	}

	// 9) 打印验收标识。
	rep := report{
		OK:              true,
		BaseURL:         cli.base,
		Code:            senderCode,
		RecipientCode:   recipient,
		PackageID:       created.TransferID,
		Chunks:          env.ChunkCount,
		ChunkSize:       env.ChunkSize,
		PlaintextSize:   env.PlaintextSize,
		PreludeLen:      env.PreludeLen,
		CiphertextBytes: env.CiphertextBytes(),
		State:           state,
		Acked:           acked,
		BlobDir:         opt.blobDir,
		LogPath:         opt.logPath,
	}
	if opt.dsn != "" {
		rep.DBURL = redactDSN(opt.dsn)
	}
	if opt.blobDir != "" {
		p := filepath.Join(opt.blobDir, created.TransferID[:2], created.TransferID)
		if acked {
			// ack 达上限后密文已被服务端物理删除，路径不存在是预期结果。
			rep.StoragePath = p + " (deleted)"
		} else {
			rep.StoragePath = p
			if _, err := os.Stat(p); err != nil {
				fmt.Fprintf(os.Stderr, "警告：存储路径不存在（--blob-dir 与服务端不一致？）：%v\n", err)
				rep.StoragePath += " (missing)"
			}
		}
	}
	if opt.dsn != "" {
		_, schema, err := probeDSN(opt.dsn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "警告：连不上 --dsn，无法确认 schema：%v\n", err)
		} else {
			rep.Schema = schema
		}
	}

	// 字段名固定（README「一条命令投递」有表），Gate 的 --deliver-cmd 按名字解析 stdout。
	fmt.Println("=== DELIVERY ===")
	fmt.Printf("code=%s\n", rep.Code)
	fmt.Printf("recipient_code=%s\n", rep.RecipientCode)
	fmt.Printf("package_id=%s\n", rep.PackageID)
	fmt.Printf("chunks=%d\n", rep.Chunks)
	fmt.Printf("chunk_size=%d\n", rep.ChunkSize)
	fmt.Printf("plaintext_size=%d\n", rep.PlaintextSize)
	fmt.Printf("prelude_len=%d\n", rep.PreludeLen)
	fmt.Printf("ciphertext_bytes=%d\n", rep.CiphertextBytes)
	fmt.Printf("state=%s\n", rep.State)
	fmt.Printf("acked=%v\n", rep.Acked)
	fmt.Printf("blob_dir=%s\n", rep.BlobDir)
	fmt.Printf("storage_path=%s\n", rep.StoragePath)
	fmt.Printf("db_url=%s\n", rep.DBURL)
	fmt.Printf("schema=%s\n", rep.Schema)
	fmt.Printf("log_path=%s\n", rep.LogPath)
	fmt.Println("================")

	if opt.jsonOut != "" {
		data, _ := json.MarshalIndent(rep, "", "  ")
		if err := os.WriteFile(opt.jsonOut, data, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "写 --json-out 失败：%v\n", err)
			return exitFailure
		}
	}
	return exitOK
}

// report 的 JSON 字段与 stdout 字段一一对应（Gate 按字段名解析）。
type report struct {
	OK              bool   `json:"ok"`
	BaseURL         string `json:"base_url"`
	Code            string `json:"code"`
	RecipientCode   string `json:"recipient_code"`
	PackageID       string `json:"package_id"`
	Chunks          uint32 `json:"chunks"`
	ChunkSize       uint32 `json:"chunk_size"`
	PlaintextSize   uint64 `json:"plaintext_size"`
	PreludeLen      int    `json:"prelude_len"`
	CiphertextBytes int64  `json:"ciphertext_bytes"`
	State           string `json:"state"`
	Acked           bool   `json:"acked"`
	BlobDir         string `json:"blob_dir"`
	StoragePath     string `json:"storage_path"`
	DBURL           string `json:"db_url"`
	Schema          string `json:"schema"`
	LogPath         string `json:"log_path"`
}

// errFailClosed 表示服务端还没接验签（503 SERVICE_UNAVAILABLE）。
var errFailClosed = errors.New("服务端验签未就绪")

func reportErr(err error) int {
	if errors.Is(err, errFailClosed) {
		fmt.Fprintf(os.Stderr, "%v：请用 YANSHU_VERIFIER=stub-allow 启动服务端再跑本工具\n", err)
		return exitFailClosed
	}
	fmt.Fprintf(os.Stderr, "投递失败：%v\n", err)
	return exitFailure
}

// ---------- HTTP ----------

type client struct {
	base string
	http *http.Client
}

type httpResult struct {
	status int
	body   []byte
	header http.Header
}

func (c *client) call(method, path string, body []byte, headers map[string]string) (httpResult, error) {
	// 429/503/超时按 5s→20s→60s 退避，最多 3 次（团队统一口径）。
	backoffs := []time.Duration{5 * time.Second, 20 * time.Second, 60 * time.Second}
	var lastErr error
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequest(method, c.base+path, bytes.NewReader(body))
		if err != nil {
			return httpResult{}, err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		if body != nil {
			req.ContentLength = int64(len(body))
		}
		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
		} else {
			raw, rerr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if rerr != nil {
				return httpResult{}, rerr
			}
			res := httpResult{status: resp.StatusCode, body: raw, header: resp.Header}
			if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable {
				return res, nil
			}
			lastErr = fmt.Errorf("服务端返回 %d: %s", resp.StatusCode, truncate(raw))
			if res.status == http.StatusServiceUnavailable &&
				strings.Contains(string(raw), string(spec.ErrServiceUnavailable)) {
				return res, errFailClosed
			}
		}
		if attempt >= len(backoffs) {
			return httpResult{}, lastErr
		}
		time.Sleep(backoffs[attempt])
	}
}

func (c *client) health() error {
	res, err := c.call(http.MethodGet, spec.PathHealthz, nil, nil)
	if err != nil {
		return err
	}
	if res.status != http.StatusOK {
		return fmt.Errorf("healthz = %d", res.status)
	}
	return nil
}

func (c *client) challenge(purpose string) (string, error) {
	body, _ := json.Marshal(spec.ChallengeRequest{Purpose: purpose})
	res, err := c.call(http.MethodPost, spec.PathChallenges, body, map[string]string{spec.HeaderContentType: spec.ContentTypeJSON})
	if err != nil {
		return "", err
	}
	if res.status != http.StatusOK {
		return "", apiError(res)
	}
	var ch spec.ChallengeResponse
	if err := json.Unmarshal(res.body, &ch); err != nil {
		return "", err
	}
	return ch.ChallengeID, nil
}

// authHeaders 组 X-YS-*；签名是占位（stub-allow 只校验形状）。
func (c *client) authHeaders(code, challengeID string) map[string]string {
	sig := make([]byte, 71)
	_, _ = rand.Read(sig)
	return map[string]string{
		spec.HeaderCode:        code,
		spec.HeaderChallengeID: challengeID,
		spec.HeaderSignature:   base64.RawURLEncoding.EncodeToString(sig),
	}
}

func (c *client) register(code string, pub []byte, nickname string) error {
	if len(pub) != 65 || pub[0] != 0x04 {
		return fmt.Errorf("公钥不是 65 字节未压缩点")
	}
	if gm.DeriveCode(pub) != code {
		return fmt.Errorf("码 %s 与公钥派生结果不一致", code)
	}
	ch, err := c.challenge(spec.PurposeRegister)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(spec.RegisterCodeRequest{
		Code:      code,
		PublicKey: base64.RawURLEncoding.EncodeToString(pub),
		Nickname:  nickname,
	})
	headers := c.authHeaders(code, ch)
	headers[spec.HeaderContentType] = spec.ContentTypeJSON
	res, err := c.call(http.MethodPost, spec.PathCodes, body, headers)
	if err != nil {
		return err
	}
	if res.status != http.StatusCreated && res.status != http.StatusOK {
		return apiError(res)
	}
	return nil
}

func (c *client) lookupCode(code string) error {
	res, err := c.call(http.MethodGet, spec.CodePath(code), nil, nil)
	if err != nil {
		return err
	}
	if res.status != http.StatusOK {
		return apiError(res)
	}
	return nil
}

func (c *client) ensureRecipient(opt options) (string, error) {
	if opt.recipient == "" {
		// 临时接收方：只为跑通流程；解包需要真正的收件人私钥，本工具不参与。
		pub := make([]byte, 65)
		pub[0] = 0x04
		if _, err := rand.Read(pub[1:]); err != nil {
			return "", err
		}
		code := gm.DeriveCode(pub)
		if err := c.register(code, pub, opt.nickname+"-recipient"); err != nil {
			return "", err
		}
		return code, nil
	}

	code := opt.recipient
	res, err := c.call(http.MethodGet, spec.CodePath(code), nil, nil)
	if err != nil {
		return "", err
	}
	switch res.status {
	case http.StatusOK:
		if opt.recipientPub == "" {
			return code, nil
		}
		var info spec.CodeLookupResponse
		if err := json.Unmarshal(res.body, &info); err != nil {
			return "", err
		}
		if info.PublicKey != opt.recipientPub {
			return "", fmt.Errorf("--recipient-pubkey 与已注册的码 %s 公钥不一致", code)
		}
		return code, nil
	case http.StatusNotFound:
		if opt.recipientPub == "" {
			return "", fmt.Errorf("接收方 %s 未注册；请同时给 --recipient-pubkey 或改用一个已注册的码", code)
		}
		pub, err := base64.RawURLEncoding.DecodeString(opt.recipientPub)
		if err != nil {
			return "", fmt.Errorf("--recipient-pubkey 不是合法 base64url：%w", err)
		}
		if gm.DeriveCode(pub) != code {
			return "", fmt.Errorf("--recipient-pubkey 派生出的码不是 %s", code)
		}
		if err := c.register(code, pub, opt.nickname+"-recipient"); err != nil {
			return "", err
		}
		return code, nil
	default:
		return "", apiError(res)
	}
}

func (c *client) createTransfer(sender, recipient string, env packet.Envelope, preludeSM3 string) (spec.CreateTransferResponse, error) {
	ch, err := c.challenge(spec.PurposeTransferCreate)
	if err != nil {
		return spec.CreateTransferResponse{}, err
	}
	// 契约里 prelude_sm3 是 base64url（不是 hex）；先用 hex 与 --sm3-cmd 对齐，再转码。
	sm3Raw, err := hex.DecodeString(preludeSM3)
	if err != nil || len(sm3Raw) != 32 {
		return spec.CreateTransferResponse{}, fmt.Errorf("prelude SM3 不是 32 字节：%q", preludeSM3)
	}
	body, _ := json.Marshal(spec.CreateTransferRequest{
		RecipientCode: recipient,
		PlaintextSize: env.PlaintextSize,
		ChunkSize:     env.ChunkSize,
		ChunkCount:    env.ChunkCount,
		PreludeLen:    uint32(env.PreludeLen),
		PreludeSM3:    base64.RawURLEncoding.EncodeToString(sm3Raw),
	})
	headers := c.authHeaders(sender, ch)
	headers[spec.HeaderContentType] = spec.ContentTypeJSON
	res, err := c.call(http.MethodPost, spec.PathTransfers, body, headers)
	if err != nil {
		return spec.CreateTransferResponse{}, err
	}
	if res.status != http.StatusCreated {
		return spec.CreateTransferResponse{}, apiError(res)
	}
	var out spec.CreateTransferResponse
	if err := json.Unmarshal(res.body, &out); err != nil {
		return spec.CreateTransferResponse{}, err
	}
	return out, nil
}

func (c *client) putPrelude(token, transferID string, prelude []byte) error {
	res, err := c.call(http.MethodPut, spec.PreludePath(transferID), prelude, map[string]string{
		spec.HeaderUploadToken: token,
		spec.HeaderContentType: spec.ContentTypeBinary,
	})
	if err != nil {
		return err
	}
	if res.status != http.StatusCreated && res.status != http.StatusNoContent {
		return apiError(res)
	}
	return nil
}

func (c *client) putChunk(token, transferID string, index int, chunk []byte) error {
	res, err := c.call(http.MethodPut, spec.ChunkPath(transferID, index), chunk, map[string]string{
		spec.HeaderUploadToken: token,
		spec.HeaderContentType: spec.ContentTypeBinary,
	})
	if err != nil {
		return err
	}
	if res.status != http.StatusCreated && res.status != http.StatusNoContent {
		return apiError(res)
	}
	return nil
}

func (c *client) complete(token, transferID string) error {
	res, err := c.call(http.MethodPost, spec.CompletePath(transferID), nil, map[string]string{
		spec.HeaderUploadToken: token,
	})
	if err != nil {
		return err
	}
	if res.status != http.StatusOK {
		return apiError(res)
	}
	return nil
}

func (c *client) downloadAll(transferID string, env packet.Envelope) (string, error) {
	res, err := c.call(http.MethodGet, spec.PreludePath(transferID), nil, nil)
	if err != nil {
		return "", err
	}
	if res.status != http.StatusOK {
		return "", apiError(res)
	}
	if !bytes.Equal(res.body, env.Prelude) {
		return "", fmt.Errorf("下载到的 prelude 与包内容不一致（len %d vs %d）", len(res.body), len(env.Prelude))
	}
	downloadID := res.header.Get(spec.HeaderDownloadID)
	if downloadID == "" {
		return "", fmt.Errorf("响应缺少 %s", spec.HeaderDownloadID)
	}
	for i, want := range env.Chunks {
		res, err := c.call(http.MethodGet, spec.ChunkPath(transferID, i), nil, map[string]string{
			spec.HeaderDownloadID: downloadID,
		})
		if err != nil {
			return "", err
		}
		if res.status != http.StatusOK {
			return "", apiError(res)
		}
		if !bytes.Equal(res.body, want) {
			return "", fmt.Errorf("第 %d 块下载内容不一致（len %d vs %d）", i, len(res.body), len(want))
		}
	}
	return downloadID, nil
}

func (c *client) ack(recipient, transferID, downloadID string) (string, error) {
	ch, err := c.challenge(spec.PurposeTransferAck)
	if err != nil {
		return "", err
	}
	headers := c.authHeaders(recipient, ch)
	headers[spec.HeaderDownloadID] = downloadID
	res, err := c.call(http.MethodPost, spec.AckPath(transferID), nil, headers)
	if err != nil {
		return "", err
	}
	if res.status != http.StatusOK {
		return "", apiError(res)
	}
	var out spec.AckResponse
	if err := json.Unmarshal(res.body, &out); err != nil {
		return "", err
	}
	return out.State, nil
}

// ---------- helpers ----------

func apiError(res httpResult) error {
	var body spec.ErrorResponse
	if err := json.Unmarshal(res.body, &body); err == nil && body.Error.Code != "" {
		if body.Error.Code == string(spec.ErrServiceUnavailable) {
			return errFailClosed
		}
		return fmt.Errorf("%s（HTTP %d）：%s", body.Error.Code, res.status, body.Error.Message)
	}
	return fmt.Errorf("HTTP %d: %s", res.status, truncate(res.body))
}

func truncate(b []byte) string {
	if len(b) > 200 {
		return string(b[:200]) + "…"
	}
	return string(b)
}

// sm3Hex 计算 prelude 的 SM3（hex）。有外部命令时优先用它，便于和端侧实现对齐。
func sm3Hex(data []byte, cmdline string) (string, error) {
	if cmdline != "" {
		out, err := exec.Command("sh", "-c", cmdline+" "+hex.EncodeToString(data)).Output()
		if err != nil {
			return "", fmt.Errorf("执行 --sm3-cmd 失败：%w", err)
		}
		s := strings.TrimSpace(string(out))
		if len(s) != 64 {
			return "", fmt.Errorf("--sm3-cmd 输出不是 64 位 hex：%q", s)
		}
		return strings.ToLower(s), nil
	}
	sum := gm.SM3(data)
	return hex.EncodeToString(sum[:]), nil
}

// redactDSN 去掉口令，只保留 user@host:port/db?params（可安全写进日志/PR）。
func redactDSN(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return "(unparsable-dsn)"
	}
	if u.User != nil {
		u.User = url.User(u.User.Username())
	}
	return u.String()
}

func probeDSN(dsn string) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return "", "", err
	}
	defer conn.Close(ctx)
	var db, schema string
	if err := conn.QueryRow(ctx, `SELECT current_database(), current_schema()`).Scan(&db, &schema); err != nil {
		return "", "", err
	}
	return db, schema, nil
}
