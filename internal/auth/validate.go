package auth

import (
	"context"
	"log"

	"github.com/reecevinto/secureapi/internal/db"
)

func GetProjectIDFromAPIKey(hash string) (string, error) {
	var projectID string

	log.Println("Looking up API key hash:", hash) // <<-- debug

	err := db.Pool.QueryRow(
		context.Background(),
		`SELECT project_id FROM api_keys
		 WHERE key_hash=$1 AND is_active=true`,
		hash,
	).Scan(&projectID)

	if err != nil {
		return "", err
	}

	return projectID, nil
}
