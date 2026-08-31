package api

import (
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/dnstrike/dnstrike/internal/dnsengine"
	"github.com/dnstrike/dnstrike/internal/scenarios"
	"github.com/dnstrike/dnstrike/internal/storage/sqlite"
	"github.com/dnstrike/dnstrike/internal/target"
	"github.com/dnstrike/dnstrike/internal/testrun"
	ws "github.com/dnstrike/dnstrike/internal/websocket"
	"github.com/dnstrike/dnstrike/pkg/models"
)

type Server struct {
	targets   *target.Service
	tests     *testrun.Service
	discovery *dnsengine.Discovery
	scenarios *scenarios.Registry
	hub       *ws.Hub
	assets    fs.FS
}

func New(targets *target.Service, tests *testrun.Service, discovery *dnsengine.Discovery, scenarios *scenarios.Registry, hub *ws.Hub, assets fs.FS) *Server {
	return &Server{targets: targets, tests: tests, discovery: discovery, scenarios: scenarios, hub: hub, assets: assets}
}

func (s *Server) Router() *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery(), requestLog(), cors())
	api := r.Group("/api")
	api.GET("/health", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })
	api.GET("/targets", s.listTargets)
	api.POST("/targets", s.createTarget)
	api.GET("/targets/:id", s.getTarget)
	api.DELETE("/targets/:id", s.deleteTarget)
	api.POST("/targets/:id/check", s.discoverTarget)
	api.GET("/scenarios", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"data": s.scenarios.List()}) })
	api.POST("/tests", s.createTest)
	api.GET("/tests", s.listTests)
	api.GET("/tests/:id", s.getTest)
	r.GET("/ws/tests/:id", s.hub.Serve)
	if s.assets != nil {
		r.NoRoute(s.serveFrontend)
	}
	return r
}
func (s *Server) listTargets(c *gin.Context) {
	items, err := s.targets.List(c.Request.Context())
	if err != nil {
		serverError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": items})
}
func (s *Server) createTarget(c *gin.Context) {
	var in models.CreateTargetInput
	if err := c.ShouldBindJSON(&in); err != nil {
		badRequest(c, "Geçersiz istek gövdesi.")
		return
	}
	item, err := s.targets.Create(c.Request.Context(), in)
	if err != nil {
		badRequest(c, err.Error())
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": item})
}
func (s *Server) getTarget(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	item, err := s.targets.Get(c.Request.Context(), id)
	if errors.Is(err, sqlite.ErrNotFound) {
		notFound(c, "Target")
		return
	}
	if err != nil {
		serverError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": item})
}
func (s *Server) deleteTarget(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	err := s.targets.Delete(c.Request.Context(), id)
	if errors.Is(err, sqlite.ErrNotFound) {
		notFound(c, "Target")
		return
	}
	if err != nil {
		serverError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
func (s *Server) discoverTarget(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	item, err := s.targets.Get(c.Request.Context(), id)
	if errors.Is(err, sqlite.ErrNotFound) {
		notFound(c, "Target")
		return
	}
	if err != nil {
		serverError(c, err)
		return
	}
	profile, err := s.discovery.Run(c.Request.Context(), item)
	if err != nil {
		badRequest(c, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": profile})
}
func parseID(c *gin.Context) (int64, bool) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id < 1 {
		badRequest(c, "Geçersiz kayıt kimliği.")
		return 0, false
	}
	return id, true
}

func (s *Server) createTest(c *gin.Context) {
	var input models.CreateTestInput
	if err := c.ShouldBindJSON(&input); err != nil {
		badRequest(c, "Geçersiz istek gövdesi.")
		return
	}
	test, err := s.tests.Create(c.Request.Context(), input)
	if errors.Is(err, sqlite.ErrNotFound) {
		notFound(c, "Target")
		return
	}
	if err != nil {
		badRequest(c, err.Error())
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": test})
}

func (s *Server) listTests(c *gin.Context) {
	filter := models.TestFilter{Scenario: c.Query("scenario"), Status: models.TestStatus(c.Query("status"))}
	if value := c.Query("target_id"); value != "" {
		id, err := strconv.ParseInt(value, 10, 64)
		if err != nil || id < 1 {
			badRequest(c, "Geçersiz target filtresi.")
			return
		}
		filter.TargetID = id
	}
	if value := c.Query("limit"); value != "" {
		limit, err := strconv.Atoi(value)
		if err != nil {
			badRequest(c, "Geçersiz sonuç limiti.")
			return
		}
		filter.Limit = limit
	}
	items, err := s.tests.List(c.Request.Context(), filter)
	if err != nil {
		badRequest(c, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": items})
}

func (s *Server) getTest(c *gin.Context) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	test, err := s.tests.Get(c.Request.Context(), id)
	if errors.Is(err, sqlite.ErrNotFound) {
		notFound(c, "Test")
		return
	}
	if err != nil {
		serverError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": test})
}
func badRequest(c *gin.Context, msg string) {
	c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{"code": "VALIDATION_ERROR", "message": msg}})
}
func notFound(c *gin.Context, resource string) {
	c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "NOT_FOUND", "message": resource + " bulunamadı."}})
}
func serverError(c *gin.Context, err error) {
	slog.Error("request failed", "error", err)
	c.JSON(http.StatusInternalServerError, gin.H{"error": gin.H{"code": "INTERNAL_ERROR", "message": "İşlem tamamlanamadı."}})
}
func requestLog() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		slog.Info("http request", "method", c.Request.Method, "path", c.Request.URL.Path, "status", c.Writer.Status())
	}
}
func cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if strings.HasPrefix(origin, "http://127.0.0.1:") || strings.HasPrefix(origin, "http://localhost:") {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Headers", "Content-Type")
			c.Header("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
		}
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
func (s *Server) serveFrontend(c *gin.Context) {
	path := strings.TrimPrefix(c.Request.URL.Path, "/")
	if path != "" {
		if f, err := s.assets.Open(path); err == nil {
			_ = f.Close()
			c.FileFromFS(path, http.FS(s.assets))
			return
		}
	}
	index, err := fs.ReadFile(s.assets, "index.html")
	if err != nil {
		serverError(c, err)
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", index)
}
