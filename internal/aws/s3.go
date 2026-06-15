// Package aws (s3.go) provides S3-compatible object storage operations.
//
// All functions require a prior call to [Initialize] so that the
// Account singleton holds a valid AWS SDK configuration. Unauthenticated
// or nil-config callers will panic at the point of client construction.
//
// Operations supported:
//   - ListBuckets             — enumerate all buckets in the account
//   - ListObjects             — list objects under a bucket prefix
//   - GetObject               — download an object's body as bytes
//   - PutObject               — upload bytes to a given bucket/key
//   - DeleteObject            — remove a single object
//   - GeneratePresignedURL    — produce a time-limited GET URL
package aws

import (
	"authgate/internal/utilities"
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	aws_v2 "github.com/aws/aws-sdk-go-v2/aws"
	aws_s3 "github.com/aws/aws-sdk-go-v2/service/s3"
)

// s3Client is a lazy-initialised singleton S3 client derived from the
// global Account config. It is safe for concurrent use once built.
var s3Client *aws_s3.Client

// ensureClient builds the S3 client exactly once.
func ensureClient() *aws_s3.Client {
	if s3Client != nil {
		return s3Client
	}
	s3Client = aws_s3.NewFromConfig(GetAccount().Config())
	return s3Client
}

// S3BucketSummary is a lightweight descriptor returned by ListBuckets.
type S3BucketSummary struct {
	Name         string    `json:"name"`
	CreationDate time.Time `json:"creation_date"`
}

// S3ObjectSummary is a lightweight descriptor returned by ListObjects.
type S3ObjectSummary struct {
	Key          string    `json:"key"`
	Size         int64     `json:"size"`
	ETag         string    `json:"etag"`
	LastModified time.Time `json:"last_modified"`
	StorageClass string    `json:"storage_class,omitempty"`
}

// S3Object represents the full output of a GetObject call.
type S3Object struct {
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

// ListBuckets returns every S3 bucket the authenticated account can see.
func ListBuckets(ctx context.Context) ([]S3BucketSummary, error) {
	client := ensureClient()

	out, err := client.ListBuckets(ctx, &aws_s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("s3 ListBuckets: %w", err)
	}

	summaries := make([]S3BucketSummary, 0, len(out.Buckets))
	for _, b := range out.Buckets {
		summaries = append(summaries, S3BucketSummary{
			Name:         aws_v2.ToString(b.Name),
			CreationDate: aws_v2.ToTime(b.CreationDate),
		})
	}

	utilities.LogProgress("s3", "ListBuckets", fmt.Sprintf("count=%d", len(summaries)))
	return summaries, nil
}

// ListObjects returns up to maxKeys objects under the given bucket/prefix.
// Pass maxKeys <= 0 to use the SDK default (1 000).
func ListObjects(ctx context.Context, bucket, prefix string, maxKeys int32) ([]S3ObjectSummary, error) {
	client := ensureClient()

	input := &aws_s3.ListObjectsV2Input{
		Bucket: aws_v2.String(bucket),
		Prefix: aws_v2.String(prefix),
	}
	if maxKeys > 0 {
		input.MaxKeys = aws_v2.Int32(maxKeys)
	}

	out, err := client.ListObjectsV2(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("s3 ListObjects(%s/%s): %w", bucket, prefix, err)
	}

	summaries := make([]S3ObjectSummary, 0, len(out.Contents))
	for _, obj := range out.Contents {
		storageClass := string(obj.StorageClass)
		if storageClass == "" {
			storageClass = "STANDARD"
		}
		summaries = append(summaries, S3ObjectSummary{
			Key:          aws_v2.ToString(obj.Key),
			Size:         aws_v2.ToInt64(obj.Size),
			ETag:         aws_v2.ToString(obj.ETag),
			LastModified: aws_v2.ToTime(obj.LastModified),
			StorageClass: storageClass,
		})
	}

	utilities.LogProgress("s3", "ListObjects",
		fmt.Sprintf("bucket=%s prefix=%s count=%d", bucket, prefix, len(summaries)))
	return summaries, nil
}

// GetObject downloads the full content of a single S3 object into memory.
// Callers handling large payloads should consider streaming with the SDK
// directly instead.
func GetObject(ctx context.Context, bucket, key string) (*S3Object, error) {
	client := ensureClient()

	out, err := client.GetObject(ctx, &aws_s3.GetObjectInput{
		Bucket: aws_v2.String(bucket),
		Key:    aws_v2.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("s3 GetObject(%s/%s): %w", bucket, key, err)
	}
	defer out.Body.Close()

	body, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, fmt.Errorf("s3 GetObject(%s/%s) read body: %w", bucket, key, err)
	}

	obj := &S3Object{
		Body:          body,
		ContentType:   aws_v2.ToString(out.ContentType),
		ContentLength: aws_v2.ToInt64(out.ContentLength),
		ETag:          aws_v2.ToString(out.ETag),
		LastModified:  aws_v2.ToTime(out.LastModified),
		Metadata:      out.Metadata,
	}

	utilities.LogProgress("s3", "GetObject",
		fmt.Sprintf("bucket=%s key=%s size=%d", bucket, key, obj.ContentLength))
	return obj, nil
}

// PutObject uploads the supplied bytes as a new S3 object. Set contentType
// to an empty string to let S3 default to binary/octet-stream.
func PutObject(ctx context.Context, bucket, key, contentType string, data []byte) (string, error) {
	client := ensureClient()

	input := &aws_s3.PutObjectInput{
		Bucket: aws_v2.String(bucket),
		Key:    aws_v2.String(key),
		Body:   bytes.NewReader(data),
	}
	if contentType != "" {
		input.ContentType = aws_v2.String(contentType)
	}

	out, err := client.PutObject(ctx, input)
	if err != nil {
		return "", fmt.Errorf("s3 PutObject(%s/%s): %w", bucket, key, err)
	}

	etag := aws_v2.ToString(out.ETag)
	utilities.LogProgress("s3", "PutObject",
		fmt.Sprintf("bucket=%s key=%s size=%d etag=%s", bucket, key, len(data), etag))
	return etag, nil
}

// DeleteObject removes a single object from the bucket. No error is returned
// when the key does not exist (S3 is idempotent).
func DeleteObject(ctx context.Context, bucket, key string) error {
	client := ensureClient()

	if _, err := client.DeleteObject(ctx, &aws_s3.DeleteObjectInput{
		Bucket: aws_v2.String(bucket),
		Key:    aws_v2.String(key),
	}); err != nil {
		return fmt.Errorf("s3 DeleteObject(%s/%s): %w", bucket, key, err)
	}

	utilities.LogProgress("s3", "DeleteObject",
		fmt.Sprintf("bucket=%s key=%s", bucket, key))
	return nil
}

// GeneratePresignedURL produces a time-limited GET URL for the specified
// object. The returned URL embeds the caller's IAM credentials as signed
// query parameters and is valid until ttl elapses.
func GeneratePresignedURL(ctx context.Context, bucket, key string, ttl time.Duration) (*PresignedURLResult, error) {
	client := ensureClient()

	psClient := aws_s3.NewPresignClient(client)

	req, err := psClient.PresignGetObject(ctx, &aws_s3.GetObjectInput{
		Bucket: aws_v2.String(bucket),
		Key:    aws_v2.String(key),
	}, func(opts *aws_s3.PresignOptions) {
		opts.Expires = ttl
	})
	if err != nil {
		return nil, fmt.Errorf("s3 PresignGetObject(%s/%s): %w", bucket, key, err)
	}

	result := &PresignedURLResult{
		URL:       req.URL,
		ExpiresAt: time.Now().Add(ttl),
	}

	utilities.LogProgress("s3", "GeneratePresignedURL",
		fmt.Sprintf("bucket=%s key=%s ttl=%s", bucket, key, ttl))
	return result, nil
}
