package db

import (
	"errors"
)

// ResolveProjectID finds projectID from API key hash
func ResolveProjectID(apiKey string) (string, error) {
	var projectID string
	err := Pool.QueryRow(
		nil,
		`SELECT project_id FROM api_keys WHERE key_hash = $1 AND is_active = true`,
		apiKey,
	).Scan(&projectID)

	if err != nil {
		return "", errors.New("API key invalid")
	}
	return projectID, nil
}
