package model

type AuthProvider int

const (
	EMAIL_AND_PASSWORD AuthProvider = iota
	GOOGLE
	GITHUB
	WEIBO
	GItCode
	WEIXIN
	TikTok
	Douyin
	Kuaishou
)
