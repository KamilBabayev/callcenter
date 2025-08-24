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

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var newUser User
	if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
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
	if err := CreateUser(database, newUser.Username, string(hashedPassword), role); err != nil {
		http.Error(w, "Error saving user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("User registered successfully!\n"))
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var loginUser User
	if err := json.NewDecoder(r.Body).Decode(&loginUser); err != nil {
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

	log.Println(userRole)
	log.Println(storedHashedPassword)
	log.Println(loginUser.Username)
	log.Println(loginUser.Password)

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
	err = database.QueryRow("SELECT id, username FROM users WHERE username=$1", username).Scan(&user.ID, &user.Username)
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
	if call.AgentID <= 0 {
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

	if err := CreateCall(database, call.Caller, call.AgentID, call.Status); err != nil {
		http.Error(w, "Error creating call", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("Call created successfully!\n"))
}
