package model

type (
	StatusCode int
	Signature  string
)

type Response struct {
	StatusCode StatusCode     `json:"status_code"`
	Signature  Signature      `json:"signature"`
	Event      *[]interface{} `json:"event"`
	Data       interface{}    `json:"data"`
}
