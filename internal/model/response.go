package model

type (
	StatusCode int
	Signature  string
	EventType  string
)

type Actor struct {
	Idenitifier string `json:"idenitifier"`
	IpAddress   string `json:"ip_address"`
	UserAgent   string `json:"user_agent"`
}

type JwtResponse struct {
	AccessToken  string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresIn    int       `json:"expires_in"`
	EventType    EventType `json:"event_type"`
	Actor        *Actor    `json:"actor"`
}

type Response struct {
	StatusCode StatusCode     `json:"status_code"`
	Signature  Signature      `json:"signature"`
	Event      *[]interface{} `json:"event"`
	Data       interface{}    `json:"data"`
}

const (
	EventTypeAuthRegister = "event.auth_register"
	EventTypeAuthLogin    = "event.auth_login"
	EventTypeAuthRefresh  = "event.auth_refresh"
	EventTypeAuthLogout   = "event.auth_logout"
)
