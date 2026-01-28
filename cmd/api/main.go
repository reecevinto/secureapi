package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/reecevinto/secureapi/internal/audit"
	"github.com/reecevinto/secureapi/internal/auth"
	"github.com/reecevinto/secureapi/internal/db"
	"github.com/reecevinto/secureapi/internal/policy"
)

func main() {
	r := gin.Default()
	if err := db.Connect(); err != nil {
		log.Fatal(err)
	}
	r.POST("/authorize", func(c *gin.Context) {
		// 1️⃣ Parse request body
		var req struct {
			APIKey   string `json:"api_key"`
			Resource string `json:"resource"`
			Action   string `json:"action"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": "invalid request"})
			return
		}

		// 2️⃣ Hash API key
		hashedKey := auth.HashAPIKey(req.APIKey)

		// 3️⃣ Find project linked to API key
		projectID, err := auth.GetProjectIDFromAPIKey(hashedKey)
		if err != nil {
			// API key invalid or revoked
			c.JSON(http.StatusForbidden, gin.H{
				"allowed": false,
			})
			return
		}

		// 4️⃣ Policy decision (zero-trust)
		allowed, _ := policy.IsAllowed(projectID, req.Resource, req.Action)

		// 5️⃣ Audit log (ALWAYS)
		result := "deny"
		if allowed {
			result = "allow"
		}

		audit.Log(
			projectID,
			req.Resource,
			req.Action,
			c.ClientIP(),
			result,
		)

		// 6️⃣ Respond
		c.JSON(http.StatusOK, gin.H{
			"allowed": allowed,
		})
	})
	r.Run(":8080")
}
