package auth

import (
	"context"
	"errors"
	"log"

	"github.com/jackc/pgx/v5"
	"github.com/reecevinto/secureapi/internal/db"
)

// GetProjectIDFromAPIKey resolves a project ID from an active API key hash
func GetProjectIDFromAPIKey(ctx context.Context, hash string) (string, error) {
	var projectID string

	log.Println("🔍 Looking up API key hash:", hash)

	err := db.Pool.QueryRow(
		ctx,
		`SELECT project_id
		 FROM api_keys
		 WHERE key_hash = $1 AND is_active = true`,
		hash,
	).Scan(&projectID)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			log.Println("❌ API key not found or inactive")
			return "", err
		}

		log.Println("⚠️ DB error during API key lookup:", err)
		return "", err
	}

	log.Println("✅ API key resolved to project:", projectID)
	return projectID, nil
}
