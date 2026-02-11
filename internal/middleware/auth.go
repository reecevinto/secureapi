package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/reecevinto/secureapi/internal/auth"
	"github.com/reecevinto/secureapi/internal/db"
)

func APIKeyAuth() gin.HandlerFunc {
	return func(c *gin.Context) {

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing authorization header",
			})
			return
		}

		// Expect: Authorization: Bearer <key>
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid authorization format",
			})
			return
		}

		rawKey := parts[1]

		// Hash incoming key same way as stored
		hashedKey := auth.HashAPIKey(rawKey)

		var projectID string
		err := db.Pool.QueryRow(
			context.Background(),
			`SELECT project_id 
			 FROM api_keys 
			 WHERE key_hash=$1 AND is_active=true`,
			hashedKey,
		).Scan(&projectID)

		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid API key",
			})
			return
		}

		// Store values in context for next middleware
		c.Set("api_key", rawKey)
		c.Set("project_id", projectID)

		c.Next()
	}
}
