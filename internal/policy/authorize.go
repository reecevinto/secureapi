package policy

import (
	"context"
	"log"

	"github.com/reecevinto/secureapi/internal/db"
)

// IsAllowed evaluates whether a project is allowed to perform an action on a resource
// Default behavior: DENY (zero-trust)
func IsAllowed(ctx context.Context, projectID, resource, action string) (bool, error) {
	var effect string

	log.Printf(
		"Checking policy → projectID=%s resource=%s action=%s",
		projectID, resource, action,
	)

	err := db.Pool.QueryRow(
		ctx,
		`SELECT effect FROM policies
		 WHERE project_id=$1 AND resource=$2 AND action=$3`,
		projectID, resource, action,
	).Scan(&effect)

	if err != nil {
		log.Println("Policy lookup: no match → default DENY")
		return false, nil
	}

	log.Println("Policy effect resolved:", effect)
	return effect == "allow", nil
}
