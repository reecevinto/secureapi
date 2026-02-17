package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/reecevinto/secureapi/internal/db"
)

func APIKeyAuth() gin.HandlerFunc {
	return func(c *gin.Context) {

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing API key",
			})
			return
		}

		// Support: Authorization: Bearer <key>
		apiKey := authHeader
		if strings.HasPrefix(authHeader, "Bearer ") {
			apiKey = strings.TrimPrefix(authHeader, "Bearer ")
		}

		var (
			projectID string
			expiresAt *time.Time
			scopes    []string
		)

		// 🔥 DAY 8 FIX: Proper bcrypt verification using pgcrypto
		err := db.Pool.QueryRow(
			c.Request.Context(),
			`
			SELECT project_id, expires_at, scopes
			FROM api_keys
			WHERE is_active = true
			AND crypt($1, key_hash) = key_hash
			`,
			apiKey,
		).Scan(&projectID, &expiresAt, &scopes)

		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid or inactive API key",
			})
			return
		}

		// ✅ Expiration check
		if expiresAt != nil && time.Now().After(*expiresAt) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "API key expired",
			})
			return
		}

		// Store values for next middleware
		c.Set("project_id", projectID)
		c.Set("scopes", scopes)
		c.Set("api_key", apiKey)

		c.Next()
	}
}
