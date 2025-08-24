package user

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type Agent struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	Role   string `json:"role"`
	Status string `json:"status"`
}

type Call struct {
	ID        int    `json:"id"`
	Caller    string `json:"caller"`
	AgentID   int    `json:"agent_id"`
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
}
