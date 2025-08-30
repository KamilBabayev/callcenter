package user

import (
	"database/sql"
)

// GetAgents retrieves all agents from the database
func GetAgents(db *sql.DB) ([]Agent, error) {
	rows, err := db.Query("SELECT id, name, status FROM agents")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []Agent
	for rows.Next() {
		var agent Agent
		if err := rows.Scan(&agent.ID, &agent.Name, &agent.Status); err != nil {
			return nil, err
		}
		agents = append(agents, agent)
	}
	return agents, nil
}

// GetCalls retrieves all calls from the database
func GetCalls(db *sql.DB) ([]Call, error) {
	rows, err := db.Query("SELECT id, caller, agent_id, status, timestamp FROM calls")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var calls []Call
	for rows.Next() {
		var call Call
		if err := rows.Scan(&call.ID, &call.Caller, &call.UserID, &call.Status, &call.Timestamp); err != nil {
			return nil, err
		}
		calls = append(calls, call)
	}
	return calls, nil
}

// CreateUser inserts a new user into the database
func CreateUser(db *sql.DB, username, hashedPassword, role string) error {
	_, err := db.Exec("INSERT INTO users (username, password, role) VALUES ($1, $2, $3)", username, hashedPassword, role)
	return err
}

// CreateAgent inserts a new agent into the database
func CreateAgent(db *sql.DB, name, status string) error {
	_, err := db.Exec("INSERT INTO agents (name, status) VALUES ($1, $2)", name, status)
	return err
}

// CreateCall inserts a new call into the database
func CreateCall(db *sql.DB, caller string, agentID int, status string) error {
	_, err := db.Exec("INSERT INTO calls (caller, agent_id, status) VALUES ($1, $2, $3)", caller, agentID, status)
	return err
}
