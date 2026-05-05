package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	registerRoutes(r)

	if err := r.Run(":1307"); err != nil {
		fmt.Println("failed to start server:", err)
	}
}