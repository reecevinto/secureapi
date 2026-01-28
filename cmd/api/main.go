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

	// 1️⃣ Connect to DB
	if err := db.Connect(); err != nil {
		log.Fatal("DB connection error:", err)
	}
	log.Println("✅ Database connected")

	r.POST("/authorize", func(c *gin.Context) {
		// 2️⃣ Parse request body
		var req struct {
			APIKey   string `json:"api_key"`
			Resource string `json:"resource"`
			Action   string `json:"action"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			log.Println("Invalid request body:", err)
			c.JSON(400, gin.H{"error": "invalid request"})
			return
		}
		log.Printf("Received request → api_key: %s, resource: %s, action: %s\n", req.APIKey, req.Resource, req.Action)

		// 3️⃣ Hash API key
		hashedKey := auth.HashAPIKey(req.APIKey)
		log.Println("Hashed API key:", hashedKey)

		// 4️⃣ Lookup project ID from API key
		projectID, err := auth.GetProjectIDFromAPIKey(hashedKey)
		if err != nil {
			log.Println("API key not found or inactive:", err)
			c.JSON(http.StatusForbidden, gin.H{"allowed": false})
			return
		}
		log.Println("Project ID found:", projectID)

		// 5️⃣ Check policy (zero-trust)
		allowed, err := policy.IsAllowed(projectID, req.Resource, req.Action)
		if err != nil {
			log.Println("Policy check error:", err)
		}
		log.Println("Policy check result → allowed:", allowed)

		// 6️⃣ Audit log
		result := "deny"
		if allowed {
			result = "allow"
		}
		audit.Log(projectID, req.Resource, req.Action, c.ClientIP(), result)
		log.Println("Audit logged:", projectID, req.Resource, req.Action, result)

		// 7️⃣ Respond
		c.JSON(http.StatusOK, gin.H{"allowed": allowed})
		log.Println("Response sent → allowed:", allowed)
	})

	r.Run(":8080")
}
