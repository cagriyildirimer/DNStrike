package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

const testAPIKey = "0123456789abcdef0123456789abcdef"

func TestNewRejectsWeakAPIKey(t *testing.T) {
	if _, err := New(nil, nil, nil, nil, nil, nil, "short"); err == nil {
		t.Fatal("expected a short API key to be rejected")
	}
}

func TestHealthIsPublicAndAPIIsProtected(t *testing.T) {
	router := testRouter(t)

	health := httptest.NewRecorder()
	router.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("health status = %d, want %d", health.Code, http.StatusOK)
	}

	protected := httptest.NewRecorder()
	router.ServeHTTP(protected, httptest.NewRequest(http.MethodGet, "/api/auth/session", nil))
	if protected.Code != http.StatusUnauthorized {
		t.Fatalf("protected status = %d, want %d", protected.Code, http.StatusUnauthorized)
	}
}

func TestAPIKeyHeadersAuthorizeRequests(t *testing.T) {
	router := testRouter(t)
	for name, header := range map[string]map[string]string{
		"bearer":  {"Authorization": "Bearer " + testAPIKey},
		"api key": {"X-DNStrike-API-Key": testAPIKey},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/api/auth/session", nil)
			for key, value := range header {
				request.Header.Set(key, value)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
			}
		})
	}
}

func TestLoginCreatesAuthenticatedSession(t *testing.T) {
	router := testRouter(t)
	login := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/auth/session", strings.NewReader(`{"api_key":"`+testAPIKey+`"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(login, request)
	if login.Code != http.StatusOK {
		t.Fatalf("login status = %d, want %d", login.Code, http.StatusOK)
	}
	cookies := login.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookie || !cookies[0].HttpOnly {
		t.Fatalf("expected one HttpOnly %s cookie, got %#v", sessionCookie, cookies)
	}

	status := httptest.NewRecorder()
	statusRequest := httptest.NewRequest(http.MethodGet, "/api/auth/session", nil)
	statusRequest.AddCookie(cookies[0])
	router.ServeHTTP(status, statusRequest)
	if status.Code != http.StatusOK {
		t.Fatalf("session status = %d, want %d", status.Code, http.StatusOK)
	}
}

func TestLoginRejectsInvalidKey(t *testing.T) {
	router := testRouter(t)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/auth/session", strings.NewReader(`{"api_key":"wrong"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestWebSocketRequiresAuthentication(t *testing.T) {
	router := testRouter(t)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/ws/tests/1", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestSessionRejectsTamperingAndExpiry(t *testing.T) {
	auth, err := newAuthenticator(testAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	auth.now = func() time.Time { return now }
	valid := auth.sessionToken(now.Add(time.Minute))
	if !auth.validSession(valid) {
		t.Fatal("expected signed, unexpired session to be valid")
	}
	if auth.validSession(valid + "tampered") {
		t.Fatal("expected tampered session to be rejected")
	}
	if auth.validSession(auth.sessionToken(now.Add(-time.Second))) {
		t.Fatal("expected expired session to be rejected")
	}
}

func testRouter(t *testing.T) http.Handler {
	t.Helper()
	gin.SetMode(gin.TestMode)
	server, err := New(nil, nil, nil, nil, nil, nil, testAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	return server.Router()
}
