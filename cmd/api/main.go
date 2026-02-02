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

	// =========================================================
	// 🔐 AUTHORIZATION ENDPOINT (DAY 2 — LOCKED)
	// =========================================================
	r.POST("/authorize", func(c *gin.Context) {
		var req struct {
			APIKey   string `json:"api_key"`
			Resource string `json:"resource"`
			Action   string `json:"action"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			log.Println("Invalid request body:", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		log.Printf(
			"Received request → api_key: %s, resource: %s, action: %s\n",
			req.APIKey, req.Resource, req.Action,
		)

		// Hash API key
		hashedKey := auth.HashAPIKey(req.APIKey)
		log.Println("Hashed API key:", hashedKey)

		// Lookup project
		projectID, err := auth.GetProjectIDFromAPIKey(hashedKey)
		if err != nil {
			log.Println("API key not found or inactive:", err)
			c.JSON(http.StatusForbidden, gin.H{"allowed": false})
			return
		}

		// Policy evaluation (zero trust)
		allowed, err := policy.IsAllowed(projectID, req.Resource, req.Action)
		if err != nil {
			log.Println("Policy check error:", err)
		}

		// Audit log (always)
		result := "deny"
		if allowed {
			result = "allow"
		}
		audit.Log(projectID, req.Resource, req.Action, c.ClientIP(), result)

		c.JSON(http.StatusOK, gin.H{"allowed": allowed})
	})

	// =========================================================
	// 🟢 DAY 3 — API KEY LIFECYCLE
	// =========================================================

	// 🔑 Create API key (shown ONCE)
	r.POST("/projects/:id/keys", func(c *gin.Context) {
		projectID := c.Param("id")

		rawKey, err := auth.GenerateAPIKey()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate key"})
			return
		}

		hashed := auth.HashAPIKey(rawKey)

		_, err = db.Pool.Exec(
			c.Request.Context(),
			`INSERT INTO api_keys (project_id, key_hash, is_active)
			 VALUES ($1, $2, true)`,
			projectID, hashed,
		)
		if err != nil {
			log.Println("Failed to store API key:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store key"})
			return
		}

		// 🔐 Return raw key ONCE
		c.JSON(http.StatusCreated, gin.H{
			"api_key": rawKey,
		})
	})

	// 🔁 Rotate API key
	r.POST("/keys/:id/rotate", func(c *gin.Context) {
		keyID := c.Param("id")

		// Deactivate old key
		_, err := db.Pool.Exec(
			c.Request.Context(),
			`UPDATE api_keys SET is_active=false WHERE id=$1`,
			keyID,
		)
		if err != nil {
			log.Println("Failed to revoke old key:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke key"})
			return
		}

		// Generate new key
		rawKey, err := auth.GenerateAPIKey()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate key"})
			return
		}
		hashed := auth.HashAPIKey(rawKey)

		_, err = db.Pool.Exec(
			c.Request.Context(),
			`INSERT INTO api_keys (project_id, key_hash, is_active)
			 SELECT project_id, $1, true FROM api_keys WHERE id=$2`,
			hashed, keyID,
		)
		if err != nil {
			log.Println("Rotation failed:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "rotation failed"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"api_key": rawKey, // shown once
		})
	})

	// 🚫 Revoke API key
	r.POST("/keys/:id/revoke", func(c *gin.Context) {
		keyID := c.Param("id")

		_, err := db.Pool.Exec(
			c.Request.Context(),
			`UPDATE api_keys SET is_active=false WHERE id=$1`,
			keyID,
		)
		if err != nil {
			log.Println("Failed to revoke key:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke key"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "revoked"})
	})

	// =========================================================

	log.Println("🚀 SecureAPI running on :8080")
	r.Run(":8080")
}
