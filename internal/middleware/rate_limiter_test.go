package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

func TestLoginRateLimiter_Allows10ThenBlocks(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/login", LoginRateLimiter(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// Reset limiter for this test IP to a fresh state
	loginLimiter = newIPRateLimiter(rate.Limit(10.0/60), 10)

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("POST", "/login", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}

	// 11th request should be rate-limited
	req := httptest.NewRequest("POST", "/login", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
}
