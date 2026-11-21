package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/daqiaoliang-coder/agent-tool-gateway/internal/config"
	"github.com/daqiaoliang-coder/agent-tool-gateway/internal/gateway"
)

func main() {
	configPath := flag.String("config", "configs/gateway.json", "path to gateway JSON configuration")
	check := flag.Bool("check", false, "validate configuration and tool schemas without loading credentials or listening")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("load configuration", "error", err)
		os.Exit(1)
	}
	if *check {
		logger.Info("configuration valid", "config_revision", cfg.Revision())
		return
	}
	g, err := gateway.NewRuntime(cfg, logger)
	if err != nil {
		logger.Error("initialize gateway", "error", err)
		os.Exit(1)
	}

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           g.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	reloadSignals := make(chan os.Signal, 1)
	signal.Notify(reloadSignals, syscall.SIGHUP)
	defer signal.Stop(reloadSignals)
	configSignals := make(chan os.Signal, 1)
	signal.Notify(configSignals, syscall.SIGUSR1)
	defer signal.Stop(configSignals)
	serveErr := make(chan error, 1)
	go func() {
		logger.Info("agent tool gateway listening", "addr", cfg.ListenAddr)
		serveErr <- server.ListenAndServe()
	}()

	for {
		select {
		case <-reloadSignals:
			_ = g.ReloadCredentials()
		case <-configSignals:
			_ = g.ReloadConfig(*configPath)
		case err := <-serveErr:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("serve gateway", "error", err)
				os.Exit(1)
			}
			return
		case <-ctx.Done():
			g.Drain()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := server.Shutdown(shutdownCtx); err != nil {
				logger.Error("shutdown gateway", "error", err)
				os.Exit(1)
			}
			return
		}
	}
}
