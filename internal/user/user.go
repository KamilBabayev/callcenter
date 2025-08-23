package user

import (
	"database/sql"
)

type User struct {
	ID       int
	Username string
	Password string
}

func InsertUser(db *sql.DB, username, hashedPassword string) error {
	_, err := db.Exec("INSERT INTO users (username, password) VALUES ($1, $2)", username, hashedPassword)
	return err
}
