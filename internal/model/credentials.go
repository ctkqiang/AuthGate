package model

// AWSAuthorisationKeys holds the three static credentials needed to
// authenticate an AWS SDK v2 client.
type AWSAuthorisationKeys struct {
	AccessKeyID     string
	SecretAccessKey string
	Region          string
}

// AliyunAuthorisationKeys holds the credentials needed to initialise
// an Alibaba Cloud SDK client (OSS, STS, etc.).
type AliyunAuthorisationKeys struct {
	AccessKeyID     string
	SecretAccessKey string
	Region          string
	Bucket          string
	Endpoint        string
}