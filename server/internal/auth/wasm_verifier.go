package auth

// 路线 B：用纯 Go 的 wasm 运行时（wazero）直接调端侧内核的 `ys_sm2_verify_der`。
//
// 为什么选它：验签只需要"把公钥/消息/签名交给已经和 GmSSL 交叉验证过的实现"，
// 服务端不再维护第二套 SM2 代码，少一个分叉源。
//
// 调用约定（源码依据：`crypto/sm/src/ffi.rs:495` @ feat/endcrypto-wasm 95a24ac）：
//   ys_sm2_verify_der(pub64, msg, msg_len, sig_der, sig_len) -> 1 通过 / 0 不通过 / 负数错误
//   公钥 **64** 字节 `X‖Y`（不含 0x04；含 0x04 的 65 字节由本包剥掉前缀）；
//   签名是 DER；userID 固定 "1234567812345678"，e = SM3(ZA‖msg)。
//   注意同族的 `ys_sm2_verify`（ffi.rs:472）收的是裸 R‖S，不是 DER —— 两者别混用。
//
// 模块 0 import、导出 `memory` + `ys_alloc`/`ys_free`；实例化失败（例如出现 import）
// 一律在启动阶段报错，不降级。

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// ErrKernelUnavailable 表示 wasm 内核没加载成功。
var ErrKernelUnavailable = errors.New("auth: wasm kernel unavailable")

// WASMVerifier 是并发安全的验签器（内部串行化对同一实例的调用）。
type WASMVerifier struct {
	rt     wazero.Runtime
	mod    api.Module
	alloc  api.Function
	free   api.Function
	verify api.Function
	mem    api.Memory

	mu     sync.Mutex
	closed atomic.Bool
}

// NewWASMVerifier 加载并实例化内核。
func NewWASMVerifier(path string) (*WASMVerifier, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: empty kernel path", ErrKernelUnavailable)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %v", ErrKernelUnavailable, path, err)
	}
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	// 内核声明 0 import；若将来引入 import，这里会直接失败而不是静默。
	mod, err := rt.InstantiateWithConfig(ctx, data, wazero.NewModuleConfig().WithName("yanshu_sm"))
	if err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("%w: instantiate: %v", ErrKernelUnavailable, err)
	}
	v := &WASMVerifier{rt: rt, mod: mod}
	for name, dst := range map[string]*api.Function{
		"ys_alloc": &v.alloc, "ys_free": &v.free, "ys_sm2_verify_der": &v.verify,
	} {
		fn := mod.ExportedFunction(name)
		if fn == nil {
			_ = rt.Close(ctx)
			return nil, fmt.Errorf("%w: missing export %s", ErrKernelUnavailable, name)
		}
		*dst = fn
	}
	v.mem = mod.Memory()
	if v.mem == nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("%w: missing exported memory", ErrKernelUnavailable)
	}
	return v, nil
}

// Version 返回内核版本（`ys_version()`，期望 0x00010000）。
func (v *WASMVerifier) Version() (uint32, error) {
	fn := v.mod.ExportedFunction("ys_version")
	if fn == nil {
		return 0, fmt.Errorf("%w: missing ys_version", ErrKernelUnavailable)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	res, err := fn.Call(context.Background())
	if err != nil || len(res) == 0 {
		return 0, fmt.Errorf("%w: ys_version: %v", ErrKernelUnavailable, err)
	}
	return uint32(res[0]), nil
}

// Verify 实现 Verifier 接口。pubKey 允许 65 字节（0x04 开头）或 64 字节 `X‖Y`。
func (v *WASMVerifier) Verify(pubKey, message, signature []byte) error {
	if v.closed.Load() {
		return ErrUnavailable
	}
	pub := pubKey
	if len(pub) == 65 && pub[0] == 0x04 {
		pub = pub[1:]
	}
	if len(pub) != 64 || len(message) == 0 || len(signature) == 0 {
		return ErrSignature
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	ctx := context.Background()

	alloc := func(data []byte) (uint32, error) {
		res, err := v.alloc.Call(ctx, uint64(len(data)))
		if err != nil || len(res) == 0 {
			return 0, fmt.Errorf("%w: ys_alloc: %v", ErrKernelUnavailable, err)
		}
		if uint32(res[0]) == 0 {
			return 0, fmt.Errorf("%w: ys_alloc returned null", ErrKernelUnavailable)
		}
		ptr := uint32(res[0])
		if !v.mem.Write(ptr, data) {
			return 0, fmt.Errorf("%w: memory write out of range", ErrKernelUnavailable)
		}
		return ptr, nil
	}

	pubPtr, err := alloc(pub)
	if err != nil {
		return err
	}
	msgPtr, err := alloc(message)
	if err != nil {
		_, _ = v.free.Call(ctx, uint64(pubPtr), uint64(len(pub)))
		return err
	}
	sigPtr, err := alloc(signature)
	if err != nil {
		_, _ = v.free.Call(ctx, uint64(pubPtr), uint64(len(pub)))
		_, _ = v.free.Call(ctx, uint64(msgPtr), uint64(len(message)))
		return err
	}
	defer func() {
		_, _ = v.free.Call(ctx, uint64(pubPtr), uint64(len(pub)))
		_, _ = v.free.Call(ctx, uint64(msgPtr), uint64(len(message)))
		_, _ = v.free.Call(ctx, uint64(sigPtr), uint64(len(signature)))
	}()

	res, err := v.verify.Call(ctx, uint64(pubPtr), uint64(msgPtr), uint64(len(message)),
		uint64(sigPtr), uint64(len(signature)))
	if err != nil || len(res) == 0 {
		return fmt.Errorf("%w: ys_sm2_verify_der: %v", ErrKernelUnavailable, err)
	}
	switch int32(uint32(res[0])) {
	case 1:
		return nil
	case 0:
		return ErrSignature
	default:
		// 负数是内核的畸形输入错误（DER 非规范、点不在曲线上等），对外同样只报"签名不合法"。
		return ErrSignature
	}
}

// Close 释放 wasm 运行时。
func (v *WASMVerifier) Close() {
	if !v.closed.CompareAndSwap(false, true) {
		return
	}
	_ = v.rt.Close(context.Background())
}
