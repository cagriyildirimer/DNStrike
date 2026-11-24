package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	apiKeyMinLength = 32
	sessionCookie   = "dnstrike_session"
	sessionTTL      = 8 * time.Hour

	// Fixed workspace credentials. This is a local lab tool; the login is a
	// convenience gate, not a hardened authentication system. Do not expose the
	// server to untrusted networks with these defaults.
	fixedUsername = "admin"
	fixedPassword = "admin"
)

type authenticator struct {
	keyHash          [sha256.Size]byte
	apiKeyConfigured bool
	signingKey       []byte
	now              func() time.Time
}

// newAuthenticator builds the session authenticator. The API key is optional: a
// non-empty key must be at least 32 characters and additionally enables
// programmatic Bearer / X-DNStrike-API-Key access, while an empty key leaves the
// username/password session login as the only way in.
func newAuthenticator(apiKey string) (*authenticator, error) {
	apiKeyConfigured := apiKey != ""
	if apiKeyConfigured && len(apiKey) < apiKeyMinLength {
		return nil, errors.New("DNSTRIKE_API_KEY must contain at least 32 characters")
	}

	seed := apiKey
	if !apiKeyConfigured {
		seed = "dnstrike-default-session-seed"
	}
	signingKey := hmac.New(sha256.New, []byte(seed))
	_, _ = signingKey.Write([]byte("dnstrike-session-signing-key"))

	a := &authenticator{
		apiKeyConfigured: apiKeyConfigured,
		signingKey:       signingKey.Sum(nil),
		now:              time.Now,
	}
	if apiKeyConfigured {
		a.keyHash = sha256.Sum256([]byte(apiKey))
	}
	return a, nil
}

// validCredentials checks the submitted workspace username/password against the
// fixed credentials in constant time.
func validCredentials(username, password string) bool {
	u := subtle.ConstantTimeCompare([]byte(username), []byte(fixedUsername))
	p := subtle.ConstantTimeCompare([]byte(password), []byte(fixedPassword))
	return u == 1 && p == 1
}

func (a *authenticator) require() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !a.authorized(c.Request) {
			c.Header("Cache-Control", "no-store")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": gin.H{
				"code":    "UNAUTHORIZED",
				"message": "Geçerli bir DNStrike oturumu veya API anahtarı gerekli.",
			}})
			return
		}
		c.Next()
	}
}

func (a *authenticator) authorized(r *http.Request) bool {
	if a.apiKeyConfigured {
		if key := strings.TrimSpace(r.Header.Get("X-DNStrike-API-Key")); key != "" && a.validAPIKey(key) {
			return true
		}
		if authorization := r.Header.Get("Authorization"); strings.HasPrefix(authorization, "Bearer ") {
			if key := strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer ")); key != "" && a.validAPIKey(key) {
				return true
			}
		}
	}
	cookie, err := r.Cookie(sessionCookie)
	return err == nil && a.validSession(cookie.Value)
}

func (a *authenticator) validAPIKey(candidate string) bool {
	if !a.apiKeyConfigured {
		return false
	}
	candidateHash := sha256.Sum256([]byte(candidate))
	return subtle.ConstantTimeCompare(candidateHash[:], a.keyHash[:]) == 1
}

func (a *authenticator) createSession(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&input); err != nil || !validCredentials(input.Username, input.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": gin.H{
			"code":    "INVALID_CREDENTIALS",
			"message": "Kullanıcı adı veya şifre geçersiz.",
		}})
		return
	}
	expiresAt := a.now().UTC().Add(sessionTTL)
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     sessionCookie,
		Value:    a.sessionToken(expiresAt),
		Path:     "/",
		MaxAge:   int(sessionTTL / time.Second),
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   requestIsHTTPS(c.Request),
		SameSite: http.SameSiteStrictMode,
	})
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"authenticated": true, "expires_at": expiresAt}})
}

func (a *authenticator) deleteSession(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
		HttpOnly: true,
		Secure:   requestIsHTTPS(c.Request),
		SameSite: http.SameSiteStrictMode,
	})
	c.Status(http.StatusNoContent)
}

func (a *authenticator) sessionStatus(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"data": gin.H{"authenticated": true}})
}

func (a *authenticator) sessionToken(expiresAt time.Time) string {
	expiry := strconv.FormatInt(expiresAt.Unix(), 10)
	signature := a.sign(expiry)
	return base64.RawURLEncoding.EncodeToString([]byte(expiry)) + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func (a *authenticator) validSession(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return false
	}
	expiryBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(signature, a.sign(string(expiryBytes))) {
		return false
	}
	expiry, err := strconv.ParseInt(string(expiryBytes), 10, 64)
	return err == nil && a.now().Unix() < expiry
}

func (a *authenticator) sign(value string) []byte {
	mac := hmac.New(sha256.New, a.signingKey)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func requestIsHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}
