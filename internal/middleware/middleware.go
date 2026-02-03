package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/reecevinto/secureapi/internal/audit"
	"github.com/reecevinto/secureapi/internal/auth"
	"github.com/reecevinto/secureapi/internal/policy"
)

// PolicyEnforcer enforces API key auth + policy authorization
func PolicyEnforcer(resource, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		// 1️⃣ Extract API key from header
		apiKey := c.GetHeader("Authorization")
		if apiKey == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing API key"})
			c.Abort()
			return
		}

		apiKey = strings.TrimPrefix(apiKey, "Bearer ")

		// 2️⃣ Hash key
		hashedKey := auth.HashAPIKey(apiKey)

		// 3️⃣ Resolve project from API key
		projectID, err := auth.GetProjectIDFromAPIKey(ctx, hashedKey)
		if err != nil {
			audit.Log(ctx, "", resource, action, c.ClientIP(), "deny")
			c.JSON(http.StatusForbidden, gin.H{"error": "invalid or inactive API key"})
			c.Abort()
			return
		}

		// 4️⃣ Policy enforcement (zero trust)
		allowed, err := policy.IsAllowed(ctx, projectID, resource, action)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "policy evaluation failed"})
			c.Abort()
			return
		}

		if !allowed {
			audit.Log(ctx, projectID, resource, action, c.ClientIP(), "deny")
			c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
			c.Abort()
			return
		}

		// 5️⃣ Attach project ID to request context
		c.Set("project_id", projectID)

		// 6️⃣ Audit success
		audit.Log(ctx, projectID, resource, action, c.ClientIP(), "allow")

		c.Next()
	}
}
