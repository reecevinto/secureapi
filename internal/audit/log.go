package audit

import (
	"context"
	"log"

	"github.com/reecevinto/secureapi/internal/db"
)

// Log records every authorization decision (allow / deny)
// This function must NEVER block the request flow
func Log(ctx context.Context, projectID, resource, action, ip, result string) {
	_, err := db.Pool.Exec(
		ctx,
		`INSERT INTO audit_logs (project_id, resource, action, ip_address, result)
		 VALUES ($1, $2, $3, $4, $5)`,
		projectID, resource, action, ip, result,
	)

	if err != nil {
		// Audit failures should be visible but NOT fatal
		log.Println("⚠️ audit log failed:", err)
	}
}
