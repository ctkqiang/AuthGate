package model

// AWSAuthorisationKeys holds the credentials needed to authenticate an
// AWS SDK v2 client.
type AWSAuthorisationKeys struct {
	AccessKeyID     string
	SecretAccessKey string
	Region          string
	Bucket          string
	DynamoDBTable   string
}

// AliyunAuthorisationKeys holds the credentials needed to initialise
// an Alibaba Cloud SDK client (OSS, STS, TableStore, etc.).
type AliyunAuthorisationKeys struct {
	AccessKeyID        string
	SecretAccessKey    string
	Region             string
	Bucket             string
	Endpoint           string
	TableStoreInstance string
	TableStoreTable    string
}

// KeysConfig holds the object-storage paths used to load the JWT
// signing keys (private.pem / public.pem) at startup.
type KeysConfig struct {
	PrivateKeyPath string
	PublicKeyPath  string
}
