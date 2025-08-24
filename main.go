package main

import (
	"log"
	"net/http"

	"callcenter/internal/admin"
	"callcenter/internal/agent"
	"callcenter/internal/auth"
	"callcenter/internal/user"
)

func main() {
	http.HandleFunc("/api/register", user.RegisterHandler)
	http.HandleFunc("/api/login", user.LoginHandler)
	http.HandleFunc("/api/profile", auth.JWTMiddleware(user.ProfileHandler))
	http.HandleFunc("/api/agents", auth.JWTMiddleware(user.AgentHandler))
	http.HandleFunc("/api/calls", auth.JWTMiddleware(user.CallHandler))
	http.HandleFunc("/api/create-agent", auth.JWTMiddleware(user.CreateAgentHandler))
	http.HandleFunc("/api/create-call", auth.JWTMiddleware(user.CreateCallHandler))
	http.HandleFunc("/api/protected", auth.JWTMiddleware(protectedHandler))
	http.HandleFunc("/api/update-agent-status", auth.JWTMiddleware(auth.RequireRoles([]string{"admin", "agent"}, agent.UpdateStatusHandler)))
	http.HandleFunc("/api/admin", auth.JWTMiddleware(auth.RequireRoles([]string{"admin"}, admin.AdminHandler)))

	log.Println("callcenter service started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("This is a protected route\n"))
}
