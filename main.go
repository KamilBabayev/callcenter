package main

import (
	"log"
	"net/http"

	"callcenter/internal/user"
)

func main() {
	http.HandleFunc("/register", user.RegisterHandler)
	http.HandleFunc("/login", user.LoginHandler)

	log.Println("callcenter service started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
