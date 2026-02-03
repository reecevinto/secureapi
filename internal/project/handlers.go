package project

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/reecevinto/secureapi/internal/db"
)

// Policy represents a policy row in your database
type Policy struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Resource  string `json:"resource"`
	Action    string `json:"action"`
	Effect    string `json:"effect"`
}

func GetPolicies(c *gin.Context) {
	projectID := c.Param("id")

	// Prepare slice to hold policies
	var policies []Policy

	// Query the database using pgx
	rows, err := db.Pool.Query(c, `
		SELECT id, project_id, resource, action, effect
		FROM policies
		WHERE project_id = $1
	`, projectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	for rows.Next() {
		var p Policy
		err := rows.Scan(&p.ID, &p.ProjectID, &p.Resource, &p.Action, &p.Effect)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		policies = append(policies, p)
	}

	c.JSON(http.StatusOK, policies)
}
