package user

import (
	"database/sql"
)

// InsertUser inserts a new user into the database
func InsertUser(db *sql.DB, username, hashedPassword string) error {
	_, err := db.Exec("INSERT INTO users (username, password) VALUES ($1, $2)", username, hashedPassword)
	return err
}

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
		if err := rows.Scan(&call.ID, &call.Caller, &call.AgentID, &call.Status, &call.Timestamp); err != nil {
			return nil, err
		}
		calls = append(calls, call)
	}
	return calls, nil
}