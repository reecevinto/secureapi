package audit

import (
	"context"

	"github.com/reecevinto/secureapi/internal/db"
)

func Log(projectID, resource, action, ip, result string) {
	db.Pool.Exec(
		context.Background(),
		`INSERT INTO audit_logs (project_id, resource, action, ip_address, result)
		 VALUES ($1,$2,$3,$4,$5)`,
		projectID, resource, action, ip, result,
	)
}
