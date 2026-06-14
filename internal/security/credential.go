package security

import (
	"authgate/internal/config"
	"authgate/internal/model"
	"errors"
)

// AWSCredentials reads the AWS credential values from config.toml's [aws]
// section via config.GetValue, validates that all three are non-empty, and
// returns them as a typed struct.
//
// Each missing value produces a distinct error message identifying which
// config key was missing so the caller knows exactly what to fix.
func AWSCredentials() (model.AWSAuthorisationKeys, error) {
	creds := model.AWSAuthorisationKeys{
		AccessKeyID:     toString(config.GetValue("aws.access_key_id")),
		SecretAccessKey: toString(config.GetValue("aws.access_key_secret")),
		Region:          toString(config.GetValue("aws.region")),
		Bucket:          toString(config.GetValue("aws.bucket")),
	}

	if creds.AccessKeyID == "" {
		return creds, errors.New("aws.access_key_id is not set in config.toml")
	}
	if creds.SecretAccessKey == "" {
		return creds, errors.New("aws.access_key_secret is not set in config.toml")
	}
	if creds.Region == "" {
		return creds, errors.New("aws.region is not set in config.toml")
	}
	return creds, nil
}

func AliyunCredentials() (model.AliyunAuthorisationKeys, error) {
	creds := model.AliyunAuthorisationKeys{
		AccessKeyID:     toString(config.GetValue("aliyun.access_key_id")),
		SecretAccessKey: toString(config.GetValue("aliyun.access_key_secret")),
		Region:          toString(config.GetValue("aliyun.region")),
		Bucket:          toString(config.GetValue("aliyun.bucket")),
		Endpoint:        toString(config.GetValue("aliyun.endpoint")),
	}

	if creds.AccessKeyID == "" {
		return creds, errors.New("aliyun.access_key_id is not set in config.toml")
	}
	if creds.SecretAccessKey == "" {
		return creds, errors.New("aliyun.access_key_secret is not set in config.toml")
	}
	if creds.Region == "" {
		return creds, errors.New("aliyun.region is not set in config.toml")
	}
	return creds, nil
}

// KeysConfig reads the [keys] section from config.toml and returns the
// paths used to locate the JWT signing PEM files in object storage.
func KeysConfig() (model.KeysConfig, error) {
	cfg := model.KeysConfig{
		PrivateKeyPath: toString(config.GetValue("keys.private_key_path")),
		PublicKeyPath:  toString(config.GetValue("keys.public_key_path")),
	}

	if cfg.PrivateKeyPath == "" {
		return cfg, errors.New("keys.private_key_path is not set in config.toml")
	}
	if cfg.PublicKeyPath == "" {
		return cfg, errors.New("keys.public_key_path is not set in config.toml")
	}
	return cfg, nil
}

// toString is a small helper that type-asserts config.GetValue's
// interface{} result to string. It returns "" on nil or wrong type.
func toString(v any) string {
	if v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}
