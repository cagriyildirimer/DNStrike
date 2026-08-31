package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/dnstrike/dnstrike/internal/api"
	"github.com/dnstrike/dnstrike/internal/dnsengine"
	"github.com/dnstrike/dnstrike/internal/scenarios"
	"github.com/dnstrike/dnstrike/internal/storage/sqlite"
	"github.com/dnstrike/dnstrike/internal/target"
	"github.com/dnstrike/dnstrike/internal/testrun"
	"github.com/dnstrike/dnstrike/internal/websocket"
	"github.com/dnstrike/dnstrike/internal/webui"
)

func main() {
	if os.Getenv("DNSTRIKE_DEBUG") != "true" {
		gin.SetMode(gin.ReleaseMode)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
	dataDir := env("DNSTRIKE_DATA_DIR", "data")
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		logger.Error("data directory", "error", err)
		os.Exit(1)
	}
	store, err := sqlite.Open(filepath.Join(dataDir, "dnstrike.db"))
	if err != nil {
		logger.Error("database startup", "error", err)
		os.Exit(1)
	}
	defer store.Close()
	registry := scenarios.DefaultRegistry()
	targetService := target.NewService(store)
	testService := testrun.NewService(store, store, registry)
	router := api.New(targetService, testService, dnsengine.NewDiscovery(3*time.Second), registry, websocket.NewHub(), webui.Assets()).Router()
	server := &http.Server{Addr: env("DNSTRIKE_ADDR", "127.0.0.1:8080"), Handler: router, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		logger.Info("DNStrike listening", "address", server.Addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server stopped", "error", err)
			os.Exit(1)
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown", "error", err)
	}
}
func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
