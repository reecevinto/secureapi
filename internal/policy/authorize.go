package policy

import (
	"context"
	"log"

	"github.com/reecevinto/secureapi/internal/db"
)

// IsAllowed evaluates whether a project is allowed to perform an action on a resource
// Evaluation order:
// 1️⃣ Any matching DENY → deny immediately
// 2️⃣ Else if any matching ALLOW → allow
// 3️⃣ Else → deny (zero-trust default)
func IsAllowed(ctx context.Context, projectID, resource, action string) (bool, error) {

	log.Printf(
		"Checking policy → projectID=%s resource=%s action=%s",
		projectID, resource, action,
	)

	rows, err := db.Pool.Query(
		ctx,
		`SELECT effect FROM policies
		 WHERE project_id=$1 AND resource=$2 AND action=$3`,
		projectID, resource, action,
	)

	if err != nil {
		return false, err
	}
	defer rows.Close()

	hasAllow := false

	for rows.Next() {
		var effect string
		if err := rows.Scan(&effect); err != nil {
			return false, err
		}

		log.Println("Policy effect found:", effect)

		// 🔴 DENY overrides everything
		if effect == "deny" {
			log.Println("Policy result: DENY (explicit deny rule)")
			return false, nil
		}

		// 🟢 Track allow
		if effect == "allow" {
			hasAllow = true
		}
	}

	// If at least one allow and no deny
	if hasAllow {
		log.Println("Policy result: ALLOW (no deny rules found)")
		return true, nil
	}

	// Zero-trust fallback
	log.Println("Policy result: DENY (no matching rules)")
	return false, nil
}
