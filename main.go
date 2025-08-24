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
	// Endpoints for admin, agent, and viewer
	http.HandleFunc("/api/profile", auth.JWTMiddleware(auth.RequireRoles([]string{"admin", "agent", "viewer"}, user.ProfileHandler)))
	http.HandleFunc("/api/login", user.LoginHandler) // Usually open to all
	http.HandleFunc("/api/register", user.RegisterHandler) // Usually open to all

	// Endpoints for admin and agent
	http.HandleFunc("/api/calls", auth.JWTMiddleware(auth.RequireRoles([]string{"admin", "agent"}, user.CallHandler)))

	// Endpoints for admin only
	http.HandleFunc("/api/agents", auth.JWTMiddleware(auth.RequireRole("admin", user.AgentHandler)))
	http.HandleFunc("/api/create-agent", auth.JWTMiddleware(auth.RequireRole("admin", user.CreateAgentHandler)))
	http.HandleFunc("/api/create-call", auth.JWTMiddleware(auth.RequireRole("admin", user.CreateCallHandler)))
	http.HandleFunc("/api/update-agent-status", auth.JWTMiddleware(auth.RequireRole("admin", agent.UpdateStatusHandler)))
	http.HandleFunc("/api/admin", auth.JWTMiddleware(auth.RequireRole("admin", admin.AdminHandler)))

	log.Println("callcenter service started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("This is a protected route\n"))
}
