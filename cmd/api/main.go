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
		ctx := c.Request.Context()

		var req struct {
			APIKey   string `json:"api_key"`
			Resource string `json:"resource"`
			Action   string `json:"action"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		hashedKey := auth.HashAPIKey(req.APIKey)
		projectID, err := auth.GetProjectIDFromAPIKey(ctx, hashedKey)
		if err != nil {
			audit.Log(ctx, "", req.Resource, req.Action, c.ClientIP(), "deny")
			c.JSON(http.StatusForbidden, gin.H{"allowed": false})
			return
		}

		allowed, err := policy.IsAllowed(ctx, projectID, req.Resource, req.Action)
		if err != nil {
			log.Println("Policy check error:", err)
		}

		result := "deny"
		if allowed {
			result = "allow"
		}

		audit.Log(ctx, projectID, req.Resource, req.Action, c.ClientIP(), result)
		c.JSON(http.StatusOK, gin.H{"allowed": allowed})
	})

	// =========================================================
	// 🟢 DAY 3 — API KEY LIFECYCLE
	// =========================================================

	r.POST("/projects/:project_id/keys", func(c *gin.Context) {
		ctx := c.Request.Context()
		projectID := c.Param("project_id")

		rawKey, err := auth.GenerateAPIKey()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate key"})
			return
		}

		hashed := auth.HashAPIKey(rawKey)
		_, err = db.Pool.Exec(
			ctx,
			`INSERT INTO api_keys (project_id, key_hash, is_active) VALUES ($1, $2, true)`,
			projectID, hashed,
		)
		if err != nil {
			log.Println("Failed to store API key:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store key"})
			return
		}

		c.JSON(http.StatusCreated, gin.H{"api_key": rawKey})
	})

	r.POST("/keys/:id/rotate", func(c *gin.Context) {
		ctx := c.Request.Context()
		keyID := c.Param("id")

		_, err := db.Pool.Exec(ctx, `UPDATE api_keys SET is_active=false WHERE id=$1`, keyID)
		if err != nil {
			log.Println("Failed to revoke old key:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke key"})
			return
		}

		rawKey, err := auth.GenerateAPIKey()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate key"})
			return
		}
		hashed := auth.HashAPIKey(rawKey)

		_, err = db.Pool.Exec(
			ctx,
			`INSERT INTO api_keys (project_id, key_hash, is_active) SELECT project_id, $1, true FROM api_keys WHERE id=$2`,
			hashed, keyID,
		)
		if err != nil {
			log.Println("Rotation failed:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "rotation failed"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"api_key": rawKey})
	})

	r.POST("/keys/:id/revoke", func(c *gin.Context) {
		ctx := c.Request.Context()
		keyID := c.Param("id")

		_, err := db.Pool.Exec(ctx, `UPDATE api_keys SET is_active=false WHERE id=$1`, keyID)
		if err != nil {
			log.Println("Failed to revoke key:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke key"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "revoked"})
	})

	// =========================================================
	// 🗂 DAY 4 — POLICY CRUD
	// =========================================================

	policies := r.Group("/projects/:project_id/policies")
	{
		// CREATE policy
		policies.POST("", func(c *gin.Context) {
			ctx := c.Request.Context()
			projectID := c.Param("project_id")

			var req struct {
				Resource string `json:"resource"`
				Action   string `json:"action"`
				Effect   string `json:"effect"`
			}

			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
				return
			}

			if req.Effect != "allow" && req.Effect != "deny" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "effect must be allow or deny"})
				return
			}

			_, err := db.Pool.Exec(
				ctx,
				`INSERT INTO policies (project_id, resource, action, effect) VALUES ($1,$2,$3,$4)`,
				projectID, req.Resource, req.Action, req.Effect,
			)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create policy"})
				return
			}

			c.JSON(http.StatusCreated, gin.H{"status": "created"})
		})

		// READ all policies
		policies.GET("", func(c *gin.Context) {
			ctx := c.Request.Context()
			projectID := c.Param("project_id")

			rows, err := db.Pool.Query(ctx, `SELECT id, resource, action, effect FROM policies WHERE project_id=$1`, projectID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch policies"})
				return
			}
			defer rows.Close()

			var list []map[string]string
			for rows.Next() {
				var id, resource, action, effect string
				rows.Scan(&id, &resource, &action, &effect)
				list = append(list, map[string]string{
					"id":       id,
					"resource": resource,
					"action":   action,
					"effect":   effect,
				})
			}

			c.JSON(http.StatusOK, list)
		})

		// UPDATE policy
		policies.PUT("/:policy_id", func(c *gin.Context) {
			ctx := c.Request.Context()
			policyID := c.Param("policy_id")

			var req struct {
				Resource string `json:"resource"`
				Action   string `json:"action"`
				Effect   string `json:"effect"`
			}

			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
				return
			}

			if req.Effect != "allow" && req.Effect != "deny" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "effect must be allow or deny"})
				return
			}

			_, err := db.Pool.Exec(
				ctx,
				`UPDATE policies SET resource=$1, action=$2, effect=$3 WHERE id=$4`,
				req.Resource, req.Action, req.Effect, policyID,
			)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"status": "updated"})
		})

		// DELETE policy
		policies.DELETE("/:policy_id", func(c *gin.Context) {
			ctx := c.Request.Context()
			policyID := c.Param("policy_id")

			_, err := db.Pool.Exec(ctx, `DELETE FROM policies WHERE id=$1`, policyID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"status": "deleted"})
		})
	}

	// =========================================================
	for _, ri := range r.Routes() {
		log.Println("Route registered:", ri.Method, ri.Path)
	}

	log.Println("🚀 SecureAPI running on :8080")
	r.Run(":8080")
}
