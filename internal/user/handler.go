package user

import (
	"callcenter/internal/auth"
	"callcenter/internal/db"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var ValidRoles = map[string]bool{
	"admin":  true,
	"viewer": true,
	"agent":  true,
}

func AllowedRolesString() string {
	roles := make([]string, 0, len(ValidRoles))
	for role := range ValidRoles {
		roles = append(roles, role)
	}
	return strings.Join(roles, ", ")
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("RegisterHandler called: %s %s", r.Method, r.URL.Path)

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var newUser User
	if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
		log.Printf("RegisterHandler error: %v", err)
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if len(newUser.Username) == 0 {
		http.Error(w, "Username can not be empty", http.StatusBadRequest)
		return
	}
	if len(newUser.Username) < 3 {
		http.Error(w, "Username must be at least 3 characters", http.StatusBadRequest)
		return
	}
	if len(newUser.Password) == 0 {
		http.Error(w, "Password can not be empty", http.StatusBadRequest)
		return
	}
	if len(newUser.Password) < 6 {
		http.Error(w, "Password must be at least 6 characters", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	database, err := db.Connect()
	if err != nil {
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}
	defer database.Close()

	var exists bool
	err = database.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username=$1)", newUser.Username).Scan(&exists)
	if err != nil {
		http.Error(w, "Error checking user existence", http.StatusInternalServerError)
		return
	}

	if exists {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	role := newUser.Role
	if role == "" {
		role = "viewer"
	}
	if !ValidRoles[role] {
		http.Error(w, "Invalid role. Allowed roles are: "+AllowedRolesString(), http.StatusBadRequest)
		// http.Error(w, "Invalid role, must be one of: admin, viewer, agent", http.StatusBadRequest)
		return
	}
	if err := CreateUser(database, newUser.Username, string(hashedPassword), role); err != nil {
		http.Error(w, "Error saving user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("User registered successfully!\n"))
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("LoginHandler called: %s %s", r.Method, r.URL.Path)

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var loginUser User
	if err := json.NewDecoder(r.Body).Decode(&loginUser); err != nil {
		log.Printf("LoginHandler error: %v", err)
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	database, err := db.Connect()
	if err != nil {
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}
	defer database.Close()

	var storedHashedPassword string
	var userRole string
	err = database.QueryRow("SELECT password, role FROM users WHERE username=$1", loginUser.Username).Scan(&storedHashedPassword, &userRole)
	if err == sql.ErrNoRows {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedHashedPassword), []byte(loginUser.Password))
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Create JWT token with role
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": loginUser.Username,
		"role":     userRole,
		"exp":      time.Now().Add(time.Hour * 72).Unix(),
	})
	tokenString, err := token.SignedString(auth.JwtKey)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	// Extract JWT token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return auth.JwtKey, nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	username, ok := claims["username"].(string)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	database, err := db.Connect()
	if err != nil {
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}
	defer database.Close()

	var user User
	err = database.QueryRow("SELECT id, username, role, is_agent, status FROM users WHERE username=$1", username).Scan(&user.ID, &user.Username, &user.Role, &user.IsAgent, &user.Status)
	if err == sql.ErrNoRows {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func CallHandler(w http.ResponseWriter, r *http.Request) {
	database, err := db.Connect()
	if err != nil {
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}
	defer database.Close()

	calls, err := GetCalls(database)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(calls)
}

func AgentHandler(w http.ResponseWriter, r *http.Request) {

	database, err := db.Connect()
	if err != nil {

		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}
	defer database.Close()

	agents, err := GetAgents(database)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(agents)

}

func CreateAgentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var agent Agent
	if err := json.NewDecoder(r.Body).Decode(&agent); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if len(agent.Name) < 2 {
		http.Error(w, "Agent name must be at least 2 characters", http.StatusBadRequest)
		return
	}
	if agent.Status == "" {
		http.Error(w, "Status is required", http.StatusBadRequest)
		return
	}

	database, err := db.Connect()
	if err != nil {
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}
	defer database.Close()

	if err := CreateAgent(database, agent.Name, agent.Status); err != nil {
		http.Error(w, "Error creating agent", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Agent created successfully!\n"))
}

func CreateCallHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var call Call
	if err := json.NewDecoder(r.Body).Decode(&call); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if len(call.Caller) < 3 {
		http.Error(w, "Caller must be at least 3 characters", http.StatusBadRequest)
		return
	}
	if call.UserID <= 0 {
		http.Error(w, "Valid agent_id is required", http.StatusBadRequest)
		return
	}
	if call.Status == "" {
		http.Error(w, "Status is required", http.StatusBadRequest)
		return
	}

	database, err := db.Connect()
	if err != nil {
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}
	defer database.Close()

	if err := CreateCall(database, call.Caller, call.UserID, call.Status); err != nil {
		http.Error(w, "Error creating call", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Call created successfully!\n"))
}

// ListUsersHandler returns all users (admin only)
func ListUsersHandler(w http.ResponseWriter, r *http.Request) {
	// Only allow GET
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract JWT token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return auth.JwtKey, nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	role, ok := claims["role"].(string)
	if !ok || role != "admin" {
		http.Error(w, "Forbidden: admin only", http.StatusForbidden)
		return
	}

	database, err := db.Connect()
	if err != nil {
		http.Error(w, "Database connection error", http.StatusInternalServerError)
		return
	}
	defer database.Close()

	rows, err := database.Query("SELECT id, username, role, is_agent, status FROM users")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.IsAgent, &u.Status)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		users = append(users, u)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}
