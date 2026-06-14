package main

import (
	"authgate/internal/aws"
	"authgate/internal/config"
	"authgate/internal/model"
)

func main() {
	config.LoadConfigurationFile("config.toml")

	providers := SupportedProvider()
	for _, _provider := range providers {
		switch _provider {
		case model.AWS:
			aws.InitializeLambdaService()
		}
	}
}

func SupportedProvider() []model.CloudPlatform {
	var enabled []model.CloudPlatform
	type providerEntry struct {
		Name model.CloudPlatform
		Key  string
	}

	entries := []providerEntry{
		{
			Name: model.AWS,
			Key:  "supported_providers.aws",
		},
		{
			Name: model.ALIYUN,
			Key:  "supported_providers.aliyun",
		},
		{
			Name: model.GCP,
			Key:  "supported_providers.gcp",
		},
		{
			Name: model.Azure,
			Key:  "supported_providers.azure",
		},
		{
			Name: model.TENCENT_CLOUD,
			Key:  "supported_providers.tencent_cloud",
		},
	}

	for _, e := range entries {
		val := config.GetValue(e.Key)
		isEnabled, ok := val.(bool)
		if ok && isEnabled {
			enabled = append(enabled, e.Name)
		}
	}

	return enabled
}
