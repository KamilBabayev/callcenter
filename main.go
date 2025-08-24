package main

import (
	"log"
	"net/http"

	"callcenter/internal/auth"
	"callcenter/internal/user"
)

func main() {
	http.HandleFunc("/register", user.RegisterHandler)
	http.HandleFunc("/login", user.LoginHandler)
	http.HandleFunc("/profile", auth.JWTMiddleware(user.ProfileHandler))
	http.HandleFunc("/agents", auth.JWTMiddleware(user.AgentHandler))
	http.HandleFunc("/calls", auth.JWTMiddleware(user.CallHandler))
	http.HandleFunc("/protected", auth.JWTMiddleware(protectedHandler))

	log.Println("callcenter service started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("This is a protected route\n"))
}
