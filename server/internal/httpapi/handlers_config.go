package httpapi

import (
	"fmt"
	"net/http"

	"github.com/spencerswagger/YanShu/server/internal/auth"
	"github.com/spencerswagger/YanShu/server/internal/spec"
)

// handleConfig 是 GET /v1/config（API.md §4.1）。
// 不返回任何密钥、内部地址或 TURN 配置（本项目没有 TURN）。
func (a *API) handleConfig(w http.ResponseWriter, r *http.Request) {
	if !a.validateQuery(w, r) {
		return
	}
	epoch, err := a.store.CurrentTokenEpoch(r.Context())
	if err != nil {
		epoch = a.cfg.TokenEpochNum
	}
	var kernelSHA, kernelVer string
	kernelExports := 0
	if ki, ok := a.verifier.(interface{ Info() auth.KernelInfo }); ok {
		info := ki.Info()
		kernelSHA = info.SHA256
		kernelVer = fmt.Sprintf("0x%08x", info.Version)
		kernelExports = info.Exports
	}
	var wsURL *string
	if a.cfg.WSURL != "" {
		u := a.cfg.WSURL
		wsURL = &u
	}
	// 这份响应里有 `server_time`（客户端算时钟偏差、做 TTL 倒计时的基准）。
	// 一旦被 CDN/反代/浏览器缓存，基准就整体偏移，**所有倒计时静默算错**，
	// 而且不会报任何错。配置本身也只在部署变更时才变，没有缓存的必要。
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("CDN-Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, spec.ConfigResponse{
		APIVersion:        spec.APIVersion,
		CryptoPackVersion: spec.CryptoPackVersion,
		ChunkSize:         spec.DefaultChunkSize,
		MaxPlaintextSize:  spec.MaxPlaintextSize,
		MaxTTLSeconds:     spec.MaxTTLSeconds,
		STUNURLs:          a.cfg.STUNURLs,
		WSURL:             wsURL,
		TokenEpoch:        epoch,
		ServerTime:        spec.FormatTime(a.now()),
		Verifier:          string(a.cfg.Verifier),
		Env:               a.cfg.Env,
		KernelSHA256:      kernelSHA,
		KernelVersion:     kernelVer,
		KernelExports:     kernelExports,
		Limits: spec.ConfigLimits{
			CodeLookupPerMin:      spec.DefaultLimits.CodeLookupPerIP.Max,
			ChallengePerMin:       spec.DefaultLimits.ChallengePerIP.Max,
			TransferCreatePerHour: spec.DefaultLimits.TransferCreatePerCode.Max,
			ChunkPutPerMin:        spec.DefaultLimits.ChunkPutPerTransfer.Max,
		},
	})
}

// handleHealthz 是运维探活，不在 API 契约内。
func (a *API) handleHealthz(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	code := http.StatusOK
	if err := a.store.Ping(r.Context()); err != nil {
		status = "degraded"
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, spec.HealthResponse{
		Status:     status,
		APIVersion: spec.APIVersion,
		Contract:   "v1",
	})
}
