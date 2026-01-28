package policy

import (
	"context"

	"github.com/reecevinto/secureapi/internal/db"
)

func IsAllowed(projectID, resource, action string) (bool, error) {
	var effect string

	err := db.Pool.QueryRow(
		context.Background(),
		`SELECT effect FROM policies
		 WHERE project_id=$1 AND resource=$2 AND action=$3`,
		projectID, resource, action,
	).Scan(&effect)

	if err != nil {
		return false, nil
	}

	return effect == "allow", nil
}
