package middleware

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

type ipRateLimiter struct {
	ips map[string]*rate.Limiter
	mu  sync.Mutex
	r   rate.Limit
	b   int
}

func newIPRateLimiter(r rate.Limit, b int) *ipRateLimiter {
	return &ipRateLimiter{
		ips: make(map[string]*rate.Limiter),
		r:   r,
		b:   b,
	}
}

func (i *ipRateLimiter) getLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()
	limiter, exists := i.ips[ip]
	if !exists {
		limiter = rate.NewLimiter(i.r, i.b)
		i.ips[ip] = limiter
	}
	return limiter
}

// loginLimiter: 10 requests per minute per IP, burst of 10
var loginLimiter = newIPRateLimiter(10.0/60, 10)

func LoginRateLimiter() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !loginLimiter.getLimiter(ip).Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "too many login attempts, please try again later",
			})
			return
		}
		c.Next()
	}
}
