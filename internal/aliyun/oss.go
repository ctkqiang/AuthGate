// Package aliyun (oss.go) provides OSS-compatible object storage
// operations, mirroring the S3 interface in aws/s3.go.
//
// All functions require a prior call to [Initialize] so that the
// Account singleton holds valid Alibaba Cloud credentials.
//
// Operations supported:
//   - ListBuckets             — enumerate all buckets in the account
//   - ListObjects             — list objects under a bucket prefix
//   - GetObject               — download an object's body as bytes
//   - PutObject               — upload bytes to a given bucket/key
//   - DeleteObject            — remove a single object
//   - GeneratePresignedURL    — produce a time-limited GET URL
package aliyun

import (
	"authgate/internal/utilities"
	"bytes"
	"fmt"
	"io"
	"time"

	aliyun_oss "github.com/aliyun/aliyun-oss-go-sdk/oss"
)

// ossClient is a lazy-initialised singleton OSS client derived from the
// global Account config. It is safe for concurrent use once built.
var ossClient *aliyun_oss.Client

// ensureClient builds the OSS client exactly once.
func ensureClient() *aliyun_oss.Client {
	if ossClient != nil {
		return ossClient
	}
	acct := GetAccount()
	client, err := aliyun_oss.New(
		acct.Endpoint(),
		acct.AccessKeyID(),
		acct.AccessKeySecret(),
	)
	if err != nil {
		panic(fmt.Sprintf("oss: failed to create client: %v", err))
	}
	ossClient = client
	return ossClient
}

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

// OSSBucketSummary is a lightweight descriptor returned by ListBuckets.
type OSSBucketSummary struct {
	Name         string    `json:"name"`
	CreationDate time.Time `json:"creation_date"`
}

// OSSObjectSummary is a lightweight descriptor returned by ListObjects.
type OSSObjectSummary struct {
	Key          string    `json:"key"`
	Size         int64     `json:"size"`
	ETag         string    `json:"etag"`
	LastModified time.Time `json:"last_modified"`
	StorageClass string    `json:"storage_class,omitempty"`
}

// OSSObject represents the full output of a GetObject call.
type OSSObject struct {
	Body          []byte            `json:"body"`
	ContentType   string            `json:"content_type"`
	ContentLength int64             `json:"content_length"`
	ETag          string            `json:"etag"`
	LastModified  time.Time         `json:"last_modified"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// PresignedURLResult carries the temporary URL and its expiry instant.
type PresignedURLResult struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ---------------------------------------------------------------------------
// Bucket operations
// ---------------------------------------------------------------------------

// ListBuckets returns every OSS bucket the authenticated account can see.
func ListBuckets() ([]OSSBucketSummary, error) {
	client := ensureClient()

	out, err := client.ListBuckets()
	if err != nil {
		return nil, fmt.Errorf("oss ListBuckets: %w", err)
	}

	summaries := make([]OSSBucketSummary, 0, len(out.Buckets))
	for _, b := range out.Buckets {
		summaries = append(summaries, OSSBucketSummary{
			Name:         b.Name,
			CreationDate: b.CreationDate,
		})
	}

	utilities.LogProgress("oss", "ListBuckets", fmt.Sprintf("count=%d", len(summaries)))
	return summaries, nil
}

// ListObjects returns up to maxKeys objects under the given bucket/prefix.
// maxKeys <= 0 uses the SDK default (100).
func ListObjects(bucket, prefix string, maxKeys int) ([]OSSObjectSummary, error) {
	client := ensureClient()
	b, err := client.Bucket(bucket)
	if err != nil {
		return nil, fmt.Errorf("oss ListObjects(%s/%s): %w", bucket, prefix, err)
	}

	opts := []aliyun_oss.Option{
		aliyun_oss.Prefix(prefix),
	}
	if maxKeys > 0 {
		opts = append(opts, aliyun_oss.MaxKeys(maxKeys))
	}

	out, err := b.ListObjects(opts...)
	if err != nil {
		return nil, fmt.Errorf("oss ListObjects(%s/%s): %w", bucket, prefix, err)
	}

	summaries := make([]OSSObjectSummary, 0, len(out.Objects))
	for _, obj := range out.Objects {
		storageClass := obj.StorageClass
		if storageClass == "" {
			storageClass = "Standard"
		}
		summaries = append(summaries, OSSObjectSummary{
			Key:          obj.Key,
			Size:         obj.Size,
			ETag:         obj.ETag,
			LastModified: obj.LastModified,
			StorageClass: storageClass,
		})
	}

	utilities.LogProgress("oss", "ListObjects",
		fmt.Sprintf("bucket=%s prefix=%s count=%d", bucket, prefix, len(summaries)))
	return summaries, nil
}

// ---------------------------------------------------------------------------
// Object operations
// ---------------------------------------------------------------------------

// GetObject downloads the full content of a single OSS object into memory.
// Callers handling large payloads should consider streaming with the SDK
// directly instead.
func GetObject(bucket, key string) (*OSSObject, error) {
	client := ensureClient()
	b, err := client.Bucket(bucket)
	if err != nil {
		return nil, fmt.Errorf("oss GetObject(%s/%s): %w", bucket, key, err)
	}

	body, err := b.GetObject(key)
	if err != nil {
		return nil, fmt.Errorf("oss GetObject(%s/%s): %w", bucket, key, err)
	}
	defer body.Close()

	data, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("oss GetObject(%s/%s) read body: %w", bucket, key, err)
	}

	obj := &OSSObject{
		Body:          data,
		ContentLength: int64(len(data)),
	}

	utilities.LogProgress("oss", "GetObject",
		fmt.Sprintf("bucket=%s key=%s size=%d", bucket, key, obj.ContentLength))
	return obj, nil
}

// PutObject uploads the supplied bytes as a new OSS object. Set
// contentType to an empty string to let OSS default to
// binary/octet-stream.
func PutObject(bucket, key, contentType string, data []byte) error {
	client := ensureClient()
	b, err := client.Bucket(bucket)
	if err != nil {
		return fmt.Errorf("oss PutObject(%s/%s): %w", bucket, key, err)
	}

	opts := []aliyun_oss.Option{}
	if contentType != "" {
		opts = append(opts, aliyun_oss.ContentType(contentType))
	}

	if err := b.PutObject(key, bytes.NewReader(data), opts...); err != nil {
		return fmt.Errorf("oss PutObject(%s/%s): %w", bucket, key, err)
	}

	utilities.LogProgress("oss", "PutObject",
		fmt.Sprintf(
			"bucket=%s key=%s size=%d",
			bucket,
			key,
			len(data),
		),
	)
	return nil
}

// DeleteObject removes a single object from the bucket. No error is
// returned when the key does not exist (OSS is idempotent for DELETE).
func DeleteObject(bucket, key string) error {
	client := ensureClient()
	b, err := client.Bucket(bucket)
	if err != nil {
		return fmt.Errorf("oss DeleteObject(%s/%s): %w", bucket, key, err)
	}

	if err := b.DeleteObject(key); err != nil {
		return fmt.Errorf("oss DeleteObject(%s/%s): %w", bucket, key, err)
	}

	utilities.LogProgress("oss", "DeleteObject",
		fmt.Sprintf("bucket=%s key=%s", bucket, key))
	return nil
}

// ---------------------------------------------------------------------------
// Presigned URL
// ---------------------------------------------------------------------------

// GeneratePresignedURL produces a time-limited GET URL for the specified
// object. The returned URL embeds the caller's AccessKey credentials as
// signed query parameters and is valid until ttl elapses.
func GeneratePresignedURL(bucket, key string, ttl time.Duration) (*PresignedURLResult, error) {
	client := ensureClient()
	b, err := client.Bucket(bucket)
	if err != nil {
		return nil, fmt.Errorf("oss SignURL(%s/%s): %w", bucket, key, err)
	}

	urlStr, err := b.SignURL(key, aliyun_oss.HTTPGet, int64(ttl.Seconds()))
	if err != nil {
		return nil, fmt.Errorf("oss SignURL(%s/%s): %w", bucket, key, err)
	}

	result := &PresignedURLResult{
		URL:       urlStr,
		ExpiresAt: time.Now().Add(ttl),
	}

	utilities.LogProgress("oss", "GeneratePresignedURL",
		fmt.Sprintf("bucket=%s key=%s ttl=%s", bucket, key, ttl))
	return result, nil
}
