package main

import (
	"log"
	"net/http"
	"time"

	"github.com/reecevinto/secureapi/internal/auth"
	"github.com/reecevinto/secureapi/internal/db"
	"github.com/reecevinto/secureapi/internal/middleware"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	// 1️⃣ Connect to DB
	if err := db.Connect(); err != nil {
		log.Fatal("DB connection error:", err)
	}
	log.Println("✅ Database connected")

	// =========================================================
	// 🔐 DAY 7 — AUTHORIZE ENDPOINT USING MIDDLEWARE + RATE LIMITING
	// =========================================================
	r.POST("/authorize",
		middleware.APIKeyAuth(),                  // Validate API Key
		middleware.RateLimiter(100, time.Minute), // 🔹 DAY 7 Rate limiting middleware
		func(c *gin.Context) {
			var req struct {
				Resource string `json:"resource"`
				Action   string `json:"action"`
			}

			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
				return
			}

			scopesInterface, _ := c.Get("scopes")
			scopes := scopesInterface.([]string)

			requiredScope := req.Resource + ":" + req.Action

			allowedByScope := false
			for _, s := range scopes {
				if s == requiredScope {
					allowedByScope = true
					break
				}
			}

			if !allowedByScope {
				c.JSON(http.StatusForbidden, gin.H{"error": "scope violation"})
				return
			}

			// Use PolicyEnforcer middleware inline
			middleware.PolicyEnforcer(req.Resource, req.Action)(c)

			// Middleware may abort on deny or invalid key
			if c.IsAborted() {
				return
			}

			// Success → allowed
			c.JSON(http.StatusOK, gin.H{"allowed": true})
		},
	)

	// =========================================================
	// 🟢 DAY 3 — API KEY LIFECYCLE
	// =========================================================
	r.POST("/projects/:project_id/keys", func(c *gin.Context) {
		ctx := c.Request.Context()
		projectID := c.Param("project_id")

		var req struct {
			ExpiresInHours int      `json:"expires_in_hours"`
			Scopes         []string `json:"scopes"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}

		rawKey, err := auth.GenerateAPIKey()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate key"})
			return
		}

		// 🔥 DAY 8 CHANGE: Remove Go hashing. Postgres will hash using crypt()
		var expiresAt *time.Time
		if req.ExpiresInHours > 0 {
			t := time.Now().Add(time.Duration(req.ExpiresInHours) * time.Hour)
			expiresAt = &t
		}

		_, err = db.Pool.Exec(ctx, `
			INSERT INTO api_keys (project_id, key_hash, is_active, expires_at, scopes)
			VALUES ($1, crypt($2, gen_salt('bf')), true, $3, $4)
		`, projectID, rawKey, expiresAt, req.Scopes)

		if err != nil {
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
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke key"})
			return
		}

		rawKey, err := auth.GenerateAPIKey()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate key"})
			return
		}

		// 🔥 DAY 8 CHANGE: Use crypt() here too
		_, err = db.Pool.Exec(ctx,
			`INSERT INTO api_keys (project_id, key_hash, is_active)
			 SELECT project_id, crypt($1, gen_salt('bf')), true
			 FROM api_keys WHERE id=$2`,
			rawKey, keyID)

		if err != nil {
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

			_, err := db.Pool.Exec(ctx,
				`INSERT INTO policies (project_id, resource, action, effect) VALUES ($1,$2,$3,$4)`,
				projectID, req.Resource, req.Action, req.Effect)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create policy"})
				return
			}

			c.JSON(http.StatusCreated, gin.H{"status": "created"})
		})

		policies.GET("", func(c *gin.Context) {
			ctx := c.Request.Context()
			projectID := c.Param("project_id")

			rows, err := db.Pool.Query(ctx,
				`SELECT id, resource, action, effect FROM policies WHERE project_id=$1`, projectID)
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

			_, err := db.Pool.Exec(ctx,
				`UPDATE policies SET resource=$1, action=$2, effect=$3 WHERE id=$4`,
				req.Resource, req.Action, req.Effect, policyID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"status": "updated"})
		})

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
	// 🔹 LOG REGISTERED ROUTES
	for _, ri := range r.Routes() {
		log.Println("Route registered:", ri.Method, ri.Path)
	}

	log.Println("🚀 SecureAPI running on :8080")
	r.Run(":8080")
}
