package config

const (
	Addr = "0.0.0.0:8000"

	IndexPath        = "/"
	HealthPath       = "/health"
	AuthRegister     = "/auth/register"
	AuthLogin        = "/auth/login"
	AuthLogout       = "/auth/logout"
	AuthRefresh      = "/auth/refresh"
	AuthWithProvider = "/auth/provider/[x]"
)
