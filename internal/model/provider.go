package model

type CloudPlatform int

const (
	AWS CloudPlatform = iota
	ALIYUN
	GCP
	Azure
	TENCENT_CLOUD
	SUPABASE
	FIREBASE
	DIGITAL_OCEAN
	CLOUDFLARE
	HUAWEICLOUD
)
