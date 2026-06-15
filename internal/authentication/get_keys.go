// Package authentication (get_keys.go) downloads the JWT signing keys
// (private.pem / public.pem) from object storage (AWS S3 or Aliyun OSS)
// and caches them in [model.PrivateKey] and [model.PublicKey].
//
// Usage:
//
//	aws-auth-keys:
//	  bucket: authgate-keys
//	  keys:
//	    private.pem
//	    public.pem
//
// LoadKeys must be called once at startup, after [aws.Initialize] or
// [aliyun.Initialize] has succeeded.
package authentication

import (
	"authgate/internal/aliyun"
	"authgate/internal/aws"
	"authgate/internal/model"
	"authgate/internal/security"
	"authgate/internal/utilities"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// supportedProvider identifies which object-storage backend is used.
type supportedProvider int

const (
	providerNone   supportedProvider = iota
	providerAWS                      // Amazon S3
	providerAliyun                   // Alibaba Cloud OSS
)

// LoadKeys downloads private.pem and public.pem from the configured
// object-storage backend, parses them into *rsa keys, and populates
// the package-level [GetPrivateKey] / [GetPublicKey] accessors.
//
// The provider is chosen automatically based on [supported_providers]
// in config.toml: AWS has priority, then Aliyun.
func LoadKeys() error {
	provider, err := detectProvider()
	if err != nil {
		return fmt.Errorf("load keys: %w", err)
	}

	keysCfg, err := security.KeysConfig()
	if err != nil {
		return fmt.Errorf("load keys: %w", err)
	}

	privPEM, pubPEM, err := downloadPEMs(provider, keysCfg)
	if err != nil {
		return fmt.Errorf("load keys: %w", err)
	}

	privKey, err := parsePrivateKey(privPEM)
	if err != nil {
		return fmt.Errorf("load keys: %w", err)
	}

	pubKey, err := parsePublicKey(pubPEM)
	if err != nil {
		return fmt.Errorf("load keys: %w", err)
	}

	model.PrivateKey = privKey
	model.PublicKey = pubKey

	utilities.LogProgress("auth", "LoadKeys", "success",
		fmt.Sprintf("provider=%d private=%s public=%s",
			provider, keysCfg.PrivateKeyPath, keysCfg.PublicKeyPath))
	return nil
}

func detectProvider() (supportedProvider, error) {
	awsCfg, _ := security.AWSCredentials()
	aliCfg, _ := security.AliyunCredentials()

	switch {
	case awsCfg.AccessKeyID != "" && awsCfg.Region != "" && awsCfg.Bucket != "":
		utilities.LogProgress("auth", "detectProvider", "aws")
		return providerAWS, nil
	case aliCfg.AccessKeyID != "" && aliCfg.Region != "" && aliCfg.Bucket != "":
		utilities.LogProgress("auth", "detectProvider", "aliyun")
		return providerAliyun, nil
	default:
		return providerNone, errors.New("no supported object-storage provider configured (check [aws]/[aliyun] in config.toml)")
	}
}

func downloadPEMs(provider supportedProvider, cfg model.KeysConfig) (privPEM, pubPEM []byte, err error) {
	switch provider {
	case providerAWS:
		return downloadFromS3(cfg)
	case providerAliyun:
		return downloadFromOSS(cfg)
	default:
		return nil, nil, errors.New("unknown provider")
	}
}

func downloadFromS3(cfg model.KeysConfig) ([]byte, []byte, error) {
	awsCreds, err := security.AWSCredentials()
	if err != nil {
		return nil, nil, err
	}
	bucket := awsCreds.Bucket

	privObj, err := aws.GetObject(context.Background(), bucket, cfg.PrivateKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("s3 get private key: %w", err)
	}

	pubObj, err := aws.GetObject(context.Background(), bucket, cfg.PublicKeyPath)
	if err != nil {
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
		return nil, nil, fmt.Errorf("oss get private key: %w", err)
	}
	pubObj, err := aliyun.GetObject(bucket, cfg.PublicKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("oss get public key: %w", err)
	}
	return privObj.Body, pubObj.Body, nil
}

// PEM parsing

func parsePrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("no PEM block found in private key data")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("PKCS#8 private key is not an RSA key")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported private key PEM type: %s", block.Type)
	}
}

func parsePublicKey(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("no PEM block found in public key data")
	}

	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("PKIX public key is not an RSA key")
		}
		return rsaKey, nil
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported public key PEM type: %s", block.Type)
	}
}

// Accessors (backward compatible)

// GetPrivateKey returns the cached RSA private key. Panics if LoadKeys
// has not been called successfully.
func GetPrivateKey() *rsa.PrivateKey {
	if model.PrivateKey == nil {
		panic("authentication: LoadKeys() must be called before GetPrivateKey()")
	}
	return model.PrivateKey
}

// GetPublicKey returns the cached RSA public key. Panics if LoadKeys
// has not been called successfully.
func GetPublicKey() *rsa.PublicKey {
	if model.PublicKey == nil {
		panic("authentication: LoadKeys() must be called before GetPublicKey()")
	}
	return model.PublicKey
}
