package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
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
	sourceIPPoolEnabled, err := envBool("DNSTRIKE_ENABLE_SOURCE_IP_POOL", false)
	if err != nil {
		logger.Error("source IP pool configuration", "error", err)
		os.Exit(1)
	}
	maxConcurrentTests, err := envInt("DNSTRIKE_MAX_CONCURRENT_TESTS", 2, 1, 32)
	if err != nil {
		logger.Error("test concurrency configuration", "error", err)
		os.Exit(1)
	}
	maxQueuedTests, err := envInt("DNSTRIKE_MAX_QUEUED_TESTS", 100, 1, 10000)
	if err != nil {
		logger.Error("test queue configuration", "error", err)
		os.Exit(1)
	}
	dataDir := env("DNSTRIKE_DATA_DIR", "data")
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		logger.Error("data directory", "error", err)
		os.Exit(1)
	}
	if err := verifyWritableDirectory(dataDir); err != nil {
		logger.Error("data directory is not writable", "path", dataDir, "error", err)
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
	testService := testrun.NewService(store, store, registry, testrun.WithSourceIPPoolEnabled(sourceIPPoolEnabled), testrun.WithMaxQueuedTests(maxQueuedTests))
	hub := websocket.NewHub()

	// Start Orchestrator
	orchestrator := testrun.NewOrchestrator(testService, store, registry, hub, maxConcurrentTests)
	orchestrator.Start()
	defer orchestrator.Stop()

	apiServer, err := api.New(targetService, testService, dnsengine.NewDiscovery(3*time.Second), registry, hub, webui.Assets(), os.Getenv("DNSTRIKE_API_KEY"))
	if err != nil {
		logger.Error("API authentication configuration", "error", err)
		os.Exit(1)
	}
	router := apiServer.Router()
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

func envBool(key string, fallback bool) (bool, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, errors.New(key + " must be true or false")
	}
	return parsed, nil
}

func envInt(key string, fallback, minimum, maximum int) (int, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, errors.New(key + " must be between " + strconv.Itoa(minimum) + " and " + strconv.Itoa(maximum))
	}
	return parsed, nil
}

func verifyWritableDirectory(path string) error {
	file, err := os.CreateTemp(path, ".dnstrike-write-check-*")
	if err != nil {
		return err
	}
	name := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	return os.Remove(name)
}
