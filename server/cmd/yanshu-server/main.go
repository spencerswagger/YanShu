// Command yanshu-server 是雁书的中转服务端。
//
// 定位：只做码/公钥登记、密文块存取、TTL/次数/撤回策略、审计与限速。
// 它**不解析** prelude 与块内容，也永远看不到文件名与明文。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/auth"
	"github.com/spencerswagger/YanShu/server/internal/blob"
	"github.com/spencerswagger/YanShu/server/internal/cleanup"
	"github.com/spencerswagger/YanShu/server/internal/config"
	"github.com/spencerswagger/YanShu/server/internal/httpapi"
	"github.com/spencerswagger/YanShu/server/internal/logging"
	"github.com/spencerswagger/YanShu/server/internal/ratelimit"
	"github.com/spencerswagger/YanShu/server/internal/store"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err.Error())
		os.Exit(1)
	}
}

func run() error {
	migrateOnly := flag.Bool("migrate-only", false, "只跑数据库迁移然后退出（常驻实例启动前自检用）")
	verifyKernel := flag.Bool("verify-kernel", false,
		"只校验内核 sha256/version/导出数后退出（CI/部署自检用）")
	flag.Parse()

	// 自检不需要数据库/密钥：只加载内核并核对白名单。
	if *verifyKernel {
		path := os.Getenv("YANSHU_KERNEL_WASM")
		if path == "" {
			path = "./kernel/yanshu_sm.wasm"
		}
		ki, err := auth.InspectKernel(path)
		if err != nil {
			return err
		}
		ok := auth.FrozenKernelSHA256[ki.SHA256]
		fmt.Printf("kernel_sha256=%s\nys_version=0x%08x\nexports=%d\nallowlisted=%t\n",
			ki.SHA256, ki.Version, ki.Exports, ok)
		if !ok {
			return fmt.Errorf("kernel sha256 %s is not in the frozen allowlist (expected %s)",
				ki.SHA256, auth.FrozenKernelSHA256List())
		}
		return nil
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	out := io.Writer(os.Stdout)
	logPath := ""
	switch {
	case cfg.LogFile != "":
		// 单文件模式（不滚动），适合容器里挂一个固定路径。
		if err := os.MkdirAll(filepath.Dir(cfg.LogFile), 0o750); err != nil {
			return fmt.Errorf("create log dir: %w", err)
		}
		f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			return fmt.Errorf("open log file: %w", err)
		}
		defer f.Close()
		out = io.MultiWriter(os.Stdout, f)
		logPath = cfg.LogFile
	case cfg.LogDir != "":
		// 按日滚动：<dir>/yanshu-server-YYYY-MM-DD.log，保留 N 天。
		rot, err := logging.New(cfg.LogDir, cfg.LogRetentionDays)
		if err != nil {
			return err
		}
		defer rot.Close()
		out = io.MultiWriter(os.Stdout, rot)
		logPath = rot.Path()
	}
	log := slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	// 起服务才校验 token 密钥；-migrate-only 不需要它。
	if !*migrateOnly {
		if err := cfg.ValidateForServe(); err != nil {
			return err
		}
	}

	if *migrateOnly {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		st, err := store.Open(ctx, cfg.DatabaseURL)
		if err != nil {
			return err
		}
		defer st.Close()
		if err := st.Migrate(ctx); err != nil {
			return err
		}
		log.Info("migrations applied", "logPath", logPath)
		return nil
	}

	log.Info("starting yanshu-server", "addr", cfg.Addr, "verifier", cfg.Verifier,
		"contract", "v1", "logPath", logPath, "logRetentionDays", cfg.LogRetentionDays)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return err
	}

	blobs, err := blob.NewDisk(cfg.BlobDir)
	if err != nil {
		return err
	}
	// EPOCH 只增不减：调小会让被吊销的旧凭据复活，直接拒绝启动（相等允许，重复启动幂等）。
	if stored, err := st.EnsureTokenEpoch(ctx, cfg.TokenEpochNum, time.Now().UTC()); err != nil {
		if errors.Is(err, store.ErrTokenEpochLower) {
			return fmt.Errorf("config: YANSHU_TOKEN_EPOCH must increase (current=%d, provided=%d); refusing to start",
				stored, cfg.TokenEpochNum)
		}
		return fmt.Errorf("check token epoch: %w", err)
	} else {
		log.Info("token epoch", "provided", cfg.TokenEpochNum, "current", stored)
	}

	verifier, err := auth.NewVerifier(string(cfg.Verifier), cfg.ResolveKernelWASM(), log)
	if err != nil {
		return err
	}
	// 内核锚定：实际 sha256 必须在内建白名单里，否则拒绝启动。
	if info, ok := verifier.(interface{ Info() auth.KernelInfo }); ok {
		ki := info.Info()
		if !auth.FrozenKernelSHA256[ki.SHA256] {
			return fmt.Errorf("kernel sha256 %s is not in the frozen allowlist (expected %s); refusing to start",
				ki.SHA256, auth.FrozenKernelSHA256List())
		}
		log.Info("kernel verified", "sha256", ki.SHA256, "version", fmt.Sprintf("0x%08x", ki.Version), "exports", ki.Exports)
	}
	if closer, ok := verifier.(interface{ Close() }); ok {
		defer closer.Close()
	}
	tokens, err := auth.NewTokenIssuer(cfg.TokenSecret)
	if err != nil {
		return err
	}

	api := httpapi.New(cfg, st, blobs, verifier, tokens, ratelimit.NewMemory(), ratelimit.NewMemoryLockout(), log)

	sweeper := cleanup.New(st, blobs, cfg.SweepInterval, log)
	go sweeper.Run(ctx)

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
