package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dnstrike/dnstrike/internal/dnsengine"
	"github.com/dnstrike/dnstrike/internal/scenarios"
	"github.com/dnstrike/dnstrike/internal/storage/sqlite"
	"github.com/dnstrike/dnstrike/internal/target"
	"github.com/dnstrike/dnstrike/internal/testrun"
	ws "github.com/dnstrike/dnstrike/internal/websocket"
	"github.com/dnstrike/dnstrike/pkg/models"
)

func TestCreateTestReturnsTooManyRequestsWhenQueueIsFull(t *testing.T) {
	store, err := sqlite.Open(filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	targetModel := models.Target{Name: "Local DNS", IPAddress: "127.0.0.1", Port: 5353, UDPEnabled: true, TCPEnabled: true}
	if err := store.CreateTarget(t.Context(), &targetModel); err != nil {
		t.Fatal(err)
	}
	registry := scenarios.DefaultRegistry()
	targetService := target.NewService(store)
	testService := testrun.NewService(store, store, registry, testrun.WithMaxQueuedTests(1))
	server, err := New(targetService, testService, dnsengine.NewDiscovery(time.Second), registry, ws.NewHub(), nil, testAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	router := server.Router()
	body := `{"target_id":1,"scenario":"benchmark","config":{}}`

	first := authenticatedJSONRequest(http.MethodPost, "/api/tests", body)
	firstResponse := httptest.NewRecorder()
	router.ServeHTTP(firstResponse, first)
	if firstResponse.Code != http.StatusCreated {
		t.Fatalf("first status = %d, want %d; body = %s", firstResponse.Code, http.StatusCreated, firstResponse.Body.String())
	}

	second := authenticatedJSONRequest(http.MethodPost, "/api/tests", body)
	secondResponse := httptest.NewRecorder()
	router.ServeHTTP(secondResponse, second)
	if secondResponse.Code != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want %d; body = %s", secondResponse.Code, http.StatusTooManyRequests, secondResponse.Body.String())
	}
	if !strings.Contains(secondResponse.Body.String(), `"code":"QUEUE_FULL"`) {
		t.Fatalf("expected QUEUE_FULL response, got %s", secondResponse.Body.String())
	}
}

func authenticatedJSONRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-DNStrike-API-Key", testAPIKey)
	return request
}
