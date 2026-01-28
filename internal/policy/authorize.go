package policy

import (
	"context"
	"log"

	"github.com/reecevinto/secureapi/internal/db"
)

func IsAllowed(projectID, resource, action string) (bool, error) {
	var effect string

	log.Printf("Checking policy → projectID: %s, resource: %s, action: %s\n", projectID, resource, action)

	err := db.Pool.QueryRow(
		context.Background(),
		`SELECT effect FROM policies
		 WHERE project_id=$1 AND resource=$2 AND action=$3`,
		projectID, resource, action,
	).Scan(&effect)

	if err != nil {
		log.Println("Policy lookup error or no row found:", err)
		return false, nil
	}

	log.Println("Policy effect found:", effect)
	return effect == "allow", nil
}
