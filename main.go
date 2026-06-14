package main

import (
	"authgate/internal/aliyun"
	"authgate/internal/aws"
	"authgate/internal/config"
	"authgate/internal/model"
	"authgate/internal/service"
	"authgate/internal/utilities"
)

func main() {
	config.LoadConfigurationFile("config.toml")

	providers := SupportedProvider()

	// Initialise every enabled provider.
	//
	// In a cloud runtime (AWS Lambda / Aliyun FC) the corresponding
	// Initialize* call blocks forever because it registers the runtime
	// handler.  In local mode every call returns immediately.
	for _, provider := range providers {
		switch provider {
		case model.AWS:
			if err := aws.InitializeLambdaService(); err != nil {
				utilities.LogProgress("AWS", "InitializeLambdaService", err.Error())
			}
		case model.ALIYUN:
			if err := aliyun.InitializeFCService(); err != nil {
				utilities.LogProgress("Aliyun", "InitializeFCService", err.Error())
			}
		case model.GCP:
			utilities.LogProgress("GCP", "HandleRequest", "Start")
		case model.Azure:
			utilities.LogProgress("Azure", "HandleRequest", "Start")
		case model.TENCENT_CLOUD:
			utilities.LogProgress("TencentCloud", "HandleRequest", "Start")
		default:
			panic("Please provide at least one cloud provider")
		}
	}

	// If a cloud runtime took over, we never reach this point.
	// Otherwise, start a single local HTTP server on Addr.
	if !service.IsLocalMode() {
		return
	}

	service.StartLocalServer()
}

// SupportedProvider reads the [supported_providers] section from config.toml
// and returns the list of cloud platforms that are enabled (set to true).
// It maps each config key (e.g. "supported_providers.aws") to its corresponding
// model.CloudPlatform constant. Providers set to false or missing from config
// are excluded from the result. Returns an empty slice if no provider is enabled.
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
