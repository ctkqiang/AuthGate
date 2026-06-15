package model

// APIGatewayEvent represents an API Gateway proxy integration event.
// It is the input format that AWS Lambda receives from API Gateway
// (REST API, HTTP API, or Function URL).
type APIGatewayEvent struct {
	HTTPMethod string            `json:"httpMethod"`
	Path       string            `json:"path"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
}
