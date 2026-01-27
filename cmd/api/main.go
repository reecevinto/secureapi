package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	r.POST("/authorize", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"allowed": false,
		})
	})

	r.Run(":8080")
}
