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

// AliyunCredentials reads the Alibaba Cloud credential values from
// config.toml's [aliyun] section via config.GetValue.
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
