// Command yanshu-server 是雁书的中转服务端。
//
// 定位：只做码/公钥登记、密文块存取、TTL/次数/撤回策略、审计与限速。
// 它**不解析** prelude 与块内容，也永远看不到文件名与明文。
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spencerswagger/YanShu/server/internal/auth"
	"github.com/spencerswagger/YanShu/server/internal/blob"
	"github.com/spencerswagger/YanShu/server/internal/cleanup"
	"github.com/spencerswagger/YanShu/server/internal/config"
	"github.com/spencerswagger/YanShu/server/internal/httpapi"
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
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log.Info("starting yanshu-server", "addr", cfg.Addr, "verifier", cfg.Verifier, "contract", "v1")

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
	verifier, err := auth.NewVerifier(string(cfg.Verifier), log)
	if err != nil {
		return err
	}
	tokens, err := auth.NewTokenIssuer(cfg.TokenSecret)
	if err != nil {
		return err
	}
	if len(cfg.TokenSecret) == 0 {
		log.Warn("YANSHU_TOKEN_SECRET is empty: upload tokens will not survive a restart")
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
