package model

// AWSAuthorisationKeys holds the three static credentials needed to
// authenticate an AWS SDK v2 client.
type AWSAuthorisationKeys struct {
	AccessKeyID     string
	SecretAccessKey string
	Region          string
	Bucket          string
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

// KeysConfig holds the object-storage paths used to load the JWT
// signing keys (private.pem / public.pem) at startup.
type KeysConfig struct {
	PrivateKeyPath string
	PublicKeyPath  string
}
