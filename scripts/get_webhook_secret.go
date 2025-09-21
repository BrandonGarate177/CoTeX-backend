package main

import (
	"fmt"
	"os"

	"github.com/brandon/cotex-backend/internal/config"
	"github.com/brandon/cotex-backend/internal/database"
	"github.com/brandon/cotex-backend/internal/logger"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run get_webhook_secret.go <repo_id>")
		fmt.Println("Example: go run get_webhook_secret.go e536c1eb-6aac-4425-a180-00b0f4ac7320")
		os.Exit(1)
	}

	repoID := os.Args[1]

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Setup logger
	logger.Setup(cfg)

	// Create database client
	db, err := database.NewClient(cfg.SupabaseURL, cfg.SupabaseServiceRoleKey)
	if err != nil {
		fmt.Printf("Error creating database client: %v\n", err)
		os.Exit(1)
	}

	// Try to get the repository
	repo, err := db.GetRepositoryByID(repoID)
	if err != nil {
		fmt.Printf("❌ Repository not found: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Webhook Secret: %s\n", repo.WebhookSecret)
}
