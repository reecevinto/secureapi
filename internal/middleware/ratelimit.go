package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type bucket struct {
	tokens     int
	lastRefill time.Time
}

var (
	mu      sync.Mutex
	buckets = make(map[string]*bucket)
)

func RateLimiter(maxRequests int, window time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {

		apiKey := c.GetString("api_key")
		if apiKey == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing API key",
			})
			return
		}

		mu.Lock()
		defer mu.Unlock()

		b, exists := buckets[apiKey]
		now := time.Now()

		if !exists {
			buckets[apiKey] = &bucket{
				tokens:     maxRequests - 1,
				lastRefill: now,
			}
			c.Next()
			return
		}

		if now.Sub(b.lastRefill) > window {
			b.tokens = maxRequests - 1
			b.lastRefill = now
			c.Next()
			return
		}

		if b.tokens <= 0 {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded",
			})
			return
		}

		b.tokens--
		c.Next()
	}
}
