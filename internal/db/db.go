package db

import (
	"context"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

var Pool *pgxpool.Pool

func Connect() error {
	// Load .env file if it exists
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	// Determine environment: "production" or default to "development"
	env := os.Getenv("APP_ENV")
	var dsn string
	if env == "production" {
		dsn = os.Getenv("DATABASE_URL_PROD")
	} else {
		dsn = os.Getenv("DATABASE_URL_DEV")
	}

	// Connect to PostgreSQL
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		return err
	}

	Pool = pool
	log.Printf("✅ Database connected (%s)\n", env)
	return nil
}
