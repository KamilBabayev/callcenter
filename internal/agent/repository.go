package agent

import "database/sql"

func UpdateAgentStatus(db *sql.DB, agentID int, status string) error {
	_, err := db.Exec("UPDATE agents SET status=$1 WHERE id=$2", status, agentID)
	return err
}
