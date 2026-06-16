package main

import (
	"authgate/internal/aliyun"
	"authgate/internal/authentication"
	"authgate/internal/aws"
	"authgate/internal/config"
	"authgate/internal/handler"
	"authgate/internal/model"
	"authgate/internal/persistence"
	"authgate/internal/security"
	"authgate/internal/service"
	"authgate/internal/utilities"
	"context"
)

func main() {
	config.LoadConfigurationFile("config.toml")

	providers := SupportedProvider()

	// Phase 1 — Initialise cloud SDKs for every enabled provider.
	//
	// This must happen before key loading and persistence because
	// S3 / OSS / DynamoDB / TableStore clients depend on the
	// global Account singleton being populated.
	for _, provider := range providers {
		switch provider {
		case model.AWS:
			if err := aws.Initialize(context.Background()); err != nil {
				utilities.Error("AWS SDK init failed: %v", err)
			}
		case model.ALIYUN:
			if err := aliyun.Initialize(); err != nil {
				utilities.Error("Aliyun SDK init failed: %v", err)
			}
		}
	}

	// Load or generate JWT signing keys.
	//   - Cloud (Lambda/FC) → download from S3/OSS; if missing, generate + upload
	//   - Local              → generate in-memory only, do NOT touch cloud storage
	if err := authentication.EnsureKeys(); err != nil {
		utilities.Error("authentication.EnsureKeys: %v", err)
	}

	// Phase 2 — Register cloud runtime handlers.
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

	// Emit startup info to CloudWatch / CloudMonitor when running in
	// cloud mode. These are no-ops in local mode.
	aws.LogStartupInfo()
	aliyun.LogStartupInfo()

	// Wire the persistence callbacks into the handler so that
	// AuthRegister / AuthLogin can read and write users to the
	// configured database backend without creating an import cycle.
	handler.PersistUserFunc = persistence.PersistUser
	handler.LookupUserFunc = persistence.LookupUser

	// Wire the security logging callback so the middleware can route
	// threat detections to CloudWatch / CloudMonitor without importing
	// aws/aliyun directly (avoids import cycle).
	handler.SecurityLogFunc = func(method, path, srcIP, ua string, matches []security.ThreatMatch) {
		aws.LogSecurityEvent(method, path, srcIP, ua, matches)
		aws.EmitSecurityMetric(matches)
		aws.LogThreatSummary(path, len(matches), security.HighestSeverity(matches).String())

		aliyun.LogSecurityEvent(method, path, srcIP, ua, matches)
		aliyun.LogThreatSummary(path, len(matches), security.HighestSeverity(matches).String())
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
