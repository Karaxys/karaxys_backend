package objectstore

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type Object struct {
	Key         string
	ContentType string
	Body        io.Reader
}

type Writer interface {
	Put(ctx context.Context, object Object) error
}

type S3Config struct {
	Bucket               string
	Region               string
	EndpointURL          string
	AccessKeyID          string
	SecretAccessKey      string
	SessionToken         string
	ForcePathStyle       bool
	ServerSideEncryption string
}

type S3Writer struct {
	client               *s3.Client
	bucket               string
	serverSideEncryption string
}

func LoadS3ConfigFromEnv() S3Config {
	return S3Config{
		Bucket:               strings.TrimSpace(os.Getenv("KARAXYS_OBJECTSTORE_BUCKET")),
		Region:               envDefault("KARAXYS_OBJECTSTORE_REGION", "us-east-1"),
		EndpointURL:          strings.TrimSpace(os.Getenv("KARAXYS_OBJECTSTORE_ENDPOINT")),
		AccessKeyID:          strings.TrimSpace(os.Getenv("KARAXYS_OBJECTSTORE_ACCESS_KEY_ID")),
		SecretAccessKey:      os.Getenv("KARAXYS_OBJECTSTORE_SECRET_ACCESS_KEY"),
		SessionToken:         os.Getenv("KARAXYS_OBJECTSTORE_SESSION_TOKEN"),
		ForcePathStyle:       boolEnvDefault("KARAXYS_OBJECTSTORE_FORCE_PATH_STYLE", false),
		ServerSideEncryption: strings.TrimSpace(os.Getenv("KARAXYS_OBJECTSTORE_SSE")),
	}
}

func NewS3Writer(ctx context.Context, cfg S3Config) (*S3Writer, error) {
	cfg.Bucket = strings.TrimSpace(cfg.Bucket)
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("object store bucket is required")
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	loadOptions := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(cfg.Region),
	}
	if cfg.AccessKeyID != "" || cfg.SecretAccessKey != "" {
		loadOptions = append(loadOptions, awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, cfg.SessionToken)))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOptions...)
	if err != nil {
		return nil, err
	}
	client := s3.NewFromConfig(awsCfg, func(options *s3.Options) {
		if cfg.EndpointURL != "" {
			options.BaseEndpoint = aws.String(cfg.EndpointURL)
		}
		options.UsePathStyle = cfg.ForcePathStyle
	})
	return &S3Writer{
		client:               client,
		bucket:               cfg.Bucket,
		serverSideEncryption: cfg.ServerSideEncryption,
	}, nil
}

func (w *S3Writer) Put(ctx context.Context, object Object) error {
	if w == nil || w.client == nil {
		return fmt.Errorf("s3 writer is not configured")
	}
	object.Key = strings.TrimSpace(object.Key)
	if object.Key == "" {
		return fmt.Errorf("object key is required")
	}
	if object.Body == nil {
		return fmt.Errorf("object body is required")
	}
	contentType := strings.TrimSpace(object.ContentType)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	input := &s3.PutObjectInput{
		Bucket:      aws.String(w.bucket),
		Key:         aws.String(object.Key),
		Body:        object.Body,
		ContentType: aws.String(contentType),
	}
	if sse := strings.TrimSpace(w.serverSideEncryption); sse != "" {
		input.ServerSideEncryption = types.ServerSideEncryption(sse)
	}
	_, err := w.client.PutObject(ctx, input)
	return err
}

func envDefault(key string, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func boolEnvDefault(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return strings.EqualFold(value, "true") || value == "1" || strings.EqualFold(value, "yes")
}
