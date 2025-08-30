package main

import (
	"log"
	"net/http"

	"callcenter/internal/admin"
	"callcenter/internal/agent"
	"callcenter/internal/auth"
	"callcenter/internal/user"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	// Endpoints for admin, agent, and viewer
	r.HandleFunc("/api/profile", auth.JWTMiddleware(auth.RequireRoles([]string{"admin", "agent", "viewer"}, user.ProfileHandler)))
	r.HandleFunc("/api/login", user.LoginHandler)
	r.HandleFunc("/api/register", user.RegisterHandler)

	// Endpoints for admin and agent
	r.HandleFunc("/api/calls", auth.JWTMiddleware(auth.RequireRoles([]string{"admin", "agent"}, user.CallHandler)))

	// Endpoints for admin only
	r.HandleFunc("/api/agents", auth.JWTMiddleware(auth.RequireRole("admin", user.AgentHandler)))
	r.HandleFunc("/api/users", auth.JWTMiddleware(auth.RequireRole("admin", user.UsersHandler))).Methods("GET", "POST")
	r.HandleFunc("/api/users/{username}", auth.JWTMiddleware(auth.RequireRole("admin", user.AdminDeleteUserHandler))).Methods("DELETE")
	r.HandleFunc("/api/create-agent", auth.JWTMiddleware(auth.RequireRole("admin", user.CreateAgentHandler)))
	r.HandleFunc("/api/create-call", auth.JWTMiddleware(auth.RequireRole("admin", user.CreateCallHandler)))
	r.HandleFunc("/api/update-agent-status", auth.JWTMiddleware(auth.RequireRole("admin", agent.UpdateStatusHandler)))
	r.HandleFunc("/api/admin", auth.JWTMiddleware(auth.RequireRole("admin", admin.AdminHandler)))

	log.Println("callcenter service started on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("This is a protected route\n"))
}
