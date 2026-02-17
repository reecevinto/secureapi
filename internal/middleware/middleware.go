package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/reecevinto/secureapi/internal/audit"
	"github.com/reecevinto/secureapi/internal/policy"
)

// PolicyEnforcer enforces policy authorization (authentication handled earlier)
func PolicyEnforcer(resource, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		// 1️⃣ Get project ID from context (set by APIKeyAuth middleware)
		projectIDInterface, exists := c.Get("project_id")
		if !exists {
			audit.Log(ctx, "", resource, action, c.ClientIP(), "deny")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authentication context"})
			c.Abort()
			return
		}

		projectID := projectIDInterface.(string)

		// 2️⃣ Policy enforcement (zero trust)
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

		// 3️⃣ Audit success
		audit.Log(ctx, projectID, resource, action, c.ClientIP(), "allow")

		c.Next()
	}
}
