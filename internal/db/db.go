package db

import (
	"database/sql"
	"log"

	_ "github.com/lib/pq"
)

func Connect() (*sql.DB, error) {
	connStr := "user=callcenter password=admin123 dbname=callcenterdb host=localhost port=5432 sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Error connecting to the database:", err)
		return nil, err
	}

	if err := db.Ping(); err != nil {
		log.Fatal("Error pinging the database:", err)
		return nil, err
	}

	return db, nil
}
