// Package authentication (get_keys.go) downloads or generates the JWT
// signing keys (private.pem / public.pem).
//
// Startup flow:
//  1. Try download from object storage (AWS S3 or Aliyun OSS).
//  2. If not found → generate a fresh RSA-2048 key pair.
//  3. In cloud mode → upload the generated keys to object storage.
//  4. In local mode → keep keys in memory only.
//
// The parsed keys are stored in [model.PrivateKey] and [model.PublicKey].
package authentication

import (
	"authgate/internal/aliyun"
	"authgate/internal/aws"
	"authgate/internal/model"
	"authgate/internal/security"
	"authgate/internal/utilities"
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"strings"
)

type keyProvider int

const (
	providerNone keyProvider = iota
	providerAWS
	providerAliyun
)

// EnsureKeys makes sure a usable RSA key pair is available for JWT
// signing. It tries to download existing keys from object storage first;
// if those are missing, it generates a new pair and — when running in a
// cloud environment — persists them back to the object store.
//
// When no object-storage backend is configured, keys are generated and
// kept in memory only (suitable for local development).
func EnsureKeys() error {
	provider, backendErr := detectBackend()

	// Try download if a backend is configured.
	if backendErr == nil {
		keysCfg, cfgErr := security.KeysConfig()
		if cfgErr == nil {
			privPEM, pubPEM, dlErr := tryDownload(provider, keysCfg)
			if dlErr == nil {
				return installKeys(privPEM, pubPEM)
			}
			utilities.LogProgress("auth", "EnsureKeys",
				fmt.Sprintf("download failed (%v) — generating new key pair", dlErr))

			privPEM, pubPEM, genErr := security.GenerateRSAKeyPair()
			if genErr != nil {
				return fmt.Errorf("ensure keys: generate: %w", genErr)
			}

			if isCloudRuntime() {
				if upErr := uploadKeys(provider, keysCfg, privPEM, pubPEM); upErr != nil {
					utilities.Error("auth: upload keys failed: %v", upErr)
				}
			} else {
				utilities.LogProgress("auth", "EnsureKeys",
					"local mode — keys kept in memory only")
			}
			return installKeys(privPEM, pubPEM)
		}
	}

	// No backend or no keys config — generate in-memory only.
	utilities.LogProgress("auth", "EnsureKeys",
		"no backend configured — generating in-memory keys")
	privPEM, pubPEM, err := security.GenerateRSAKeyPair()
	if err != nil {
		return fmt.Errorf("ensure keys: generate: %w", err)
	}
	return installKeys(privPEM, pubPEM)
}

func detectBackend() (keyProvider, error) {
	awsCfg, _ := security.AWSCredentials()
	aliCfg, _ := security.AliyunCredentials()

	switch {
	case awsCfg.AccessKeyID != "" && awsCfg.Region != "" && awsCfg.Bucket != "" && aws.Ready():
		return providerAWS, nil
	case aliCfg.AccessKeyID != "" && aliCfg.Region != "" && aliCfg.Bucket != "" && aliyun.Ready():
		return providerAliyun, nil
	default:
		return providerNone, errors.New("no object-storage backend ready — running in memory-only mode")
	}
}

func tryDownload(provider keyProvider, cfg model.KeysConfig) (privPEM, pubPEM []byte, err error) {
	switch provider {
	case providerAWS:
		return downloadFromS3(cfg)
	case providerAliyun:
		return downloadFromOSS(cfg)
	default:
		return nil, nil, errors.New("no backend")
	}
}

func uploadKeys(provider keyProvider, cfg model.KeysConfig, privPEM, pubPEM []byte) error {
	switch provider {
	case providerAWS:
		return uploadToS3(cfg, privPEM, pubPEM)
	case providerAliyun:
		return uploadToOSS(cfg, privPEM, pubPEM)
	default:
		return errors.New("no backend")
	}
}

func isCloudRuntime() bool {
	if _, ok := os.LookupEnv("_LAMBDA_SERVER_PORT"); ok {
		return true
	}
	if _, ok := os.LookupEnv("AWS_LAMBDA_RUNTIME_API"); ok {
		return true
	}
	if _, ok := os.LookupEnv("FC_FUNCTION_NAME"); ok {
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Download
// ---------------------------------------------------------------------------

func downloadFromS3(cfg model.KeysConfig) ([]byte, []byte, error) {
	awsCreds, err := security.AWSCredentials()
	if err != nil {
		return nil, nil, err
	}
	bucket := awsCreds.Bucket

	privObj, err := aws.GetObject(context.Background(), bucket, cfg.PrivateKeyPath)
	if err != nil {
		if strings.Contains(err.Error(), "NoSuchKey") || strings.Contains(err.Error(), "404") {
			return nil, nil, fmt.Errorf("s3 key not found: %s/%s", bucket, cfg.PrivateKeyPath)
		}
		return nil, nil, fmt.Errorf("s3 get private key: %w", err)
	}

	pubObj, err := aws.GetObject(context.Background(), bucket, cfg.PublicKeyPath)
	if err != nil {
		if strings.Contains(err.Error(), "NoSuchKey") || strings.Contains(err.Error(), "404") {
			return nil, nil, fmt.Errorf("s3 key not found: %s/%s", bucket, cfg.PublicKeyPath)
		}
		return nil, nil, fmt.Errorf("s3 get public key: %w", err)
	}
	return privObj.Body, pubObj.Body, nil
}

func downloadFromOSS(cfg model.KeysConfig) ([]byte, []byte, error) {
	aliCreds, err := security.AliyunCredentials()
	if err != nil {
		return nil, nil, err
	}
	bucket := aliCreds.Bucket

	privObj, err := aliyun.GetObject(bucket, cfg.PrivateKeyPath)
	if err != nil {
		if strings.Contains(err.Error(), "NoSuchKey") || strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "not exist") {
			return nil, nil, fmt.Errorf("oss key not found: %s/%s", bucket, cfg.PrivateKeyPath)
		}
		return nil, nil, fmt.Errorf("oss get private key: %w", err)
	}
	pubObj, err := aliyun.GetObject(bucket, cfg.PublicKeyPath)
	if err != nil {
		if strings.Contains(err.Error(), "NoSuchKey") || strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "not exist") {
			return nil, nil, fmt.Errorf("oss key not found: %s/%s", bucket, cfg.PublicKeyPath)
		}
		return nil, nil, fmt.Errorf("oss get public key: %w", err)
	}
	return privObj.Body, pubObj.Body, nil
}

// ---------------------------------------------------------------------------
// Upload
// ---------------------------------------------------------------------------

func uploadToS3(cfg model.KeysConfig, privPEM, pubPEM []byte) error {
	awsCreds, err := security.AWSCredentials()
	if err != nil {
		return err
	}
	bucket := awsCreds.Bucket

	if _, err := aws.PutObject(context.Background(), bucket, cfg.PrivateKeyPath, "application/x-pem-file", privPEM); err != nil {
		return fmt.Errorf("s3 upload private key: %w", err)
	}
	utilities.LogProgress("auth", "uploadToS3", fmt.Sprintf("uploaded %s", cfg.PrivateKeyPath))

	if _, err := aws.PutObject(context.Background(), bucket, cfg.PublicKeyPath, "application/x-pem-file", pubPEM); err != nil {
		return fmt.Errorf("s3 upload public key: %w", err)
	}
	utilities.LogProgress("auth", "uploadToS3", fmt.Sprintf("uploaded %s", cfg.PublicKeyPath))
	return nil
}

func uploadToOSS(cfg model.KeysConfig, privPEM, pubPEM []byte) error {
	aliCreds, err := security.AliyunCredentials()
	if err != nil {
		return err
	}
	bucket := aliCreds.Bucket

	if err := aliyun.PutObject(bucket, cfg.PrivateKeyPath, "application/x-pem-file", privPEM); err != nil {
		return fmt.Errorf("oss upload private key: %w", err)
	}
	utilities.LogProgress("auth", "uploadToOSS", fmt.Sprintf("uploaded %s", cfg.PrivateKeyPath))

	if err := aliyun.PutObject(bucket, cfg.PublicKeyPath, "application/x-pem-file", pubPEM); err != nil {
		return fmt.Errorf("oss upload public key: %w", err)
	}
	utilities.LogProgress("auth", "uploadToOSS", fmt.Sprintf("uploaded %s", cfg.PublicKeyPath))
	return nil
}

// ---------------------------------------------------------------------------
// Install
// ---------------------------------------------------------------------------

func installKeys(privPEM, pubPEM []byte) error {
	privKey, err := parsePrivateKey(privPEM)
	if err != nil {
		return fmt.Errorf("install: private key: %w", err)
	}
	pubKey, err := parsePublicKey(pubPEM)
	if err != nil {
		return fmt.Errorf("install: public key: %w", err)
	}

	model.PrivateKey = privKey
	model.PublicKey = pubKey

	utilities.LogProgress("auth", "installKeys", "keys loaded into memory",
		fmt.Sprintf("private=%d bytes public=%d bytes", len(privPEM), len(pubPEM)))
	return nil
}

// ---------------------------------------------------------------------------
// PEM parsing (shared with legacy LoadKeys)
// ---------------------------------------------------------------------------

func parsePrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	return security.ParsePrivateKeyPEM(pemData)
}

func parsePublicKey(pemData []byte) (*rsa.PublicKey, error) {
	return security.ParsePublicKeyPEM(pemData)
}

// ---------------------------------------------------------------------------
// Legacy API (backward compatible)
// ---------------------------------------------------------------------------

// LoadKeys downloads private.pem and public.pem from the configured
// object-storage backend. Prefer [EnsureKeys] for new code — it will
// auto-generate keys when they are missing.
//
// Deprecated: use [EnsureKeys] instead.
func LoadKeys() error {
	return EnsureKeys()
}

// GetPrivateKey returns the cached RSA private key. Panics if keys have
// not been loaded.
func GetPrivateKey() *rsa.PrivateKey {
	if model.PrivateKey == nil {
		panic("authentication: keys not loaded — call EnsureKeys() first")
	}
	return model.PrivateKey
}

// GetPublicKey returns the cached RSA public key. Panics if keys have
// not been loaded.
func GetPublicKey() *rsa.PublicKey {
	if model.PublicKey == nil {
		panic("authentication: keys not loaded — call EnsureKeys() first")
	}
	return model.PublicKey
}
