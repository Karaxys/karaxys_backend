package db

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	defaultTrafficLogMaxEvents = 1000
	defaultTrafficLogTTL       = 24 * time.Hour
	mongoConnectTimeout        = 10 * time.Second
	mongoPingTimeout           = 10 * time.Second
	mongoIndexTimeout          = 60 * time.Second
)

type DB struct {
	Client               *mongo.Client
	Name                 string
	Logs                 *mongo.Collection
	TrafficConversations *mongo.Collection
	IngestionLogs        *mongo.Collection
	IngestDeadLetters    *mongo.Collection
	ScanJobs             *mongo.Collection
	ScanResults          *mongo.Collection
	ScanSecrets          *mongo.Collection
	AuditLogs            *mongo.Collection
	Accounts             *mongo.Collection
	AccountSettings      *mongo.Collection
	Users                *mongo.Collection
	Sessions             *mongo.Collection
	DataSources          *mongo.Collection
	AgentEnrollments     *mongo.Collection
	Agents               *mongo.Collection
	APIParameters        *mongo.Collection
	TrafficSamples       *mongo.Collection
	SensitiveSamples     *mongo.Collection
	TrafficMetrics       *mongo.Collection
	TrafficMetricEvents  *mongo.Collection
	LogRetention         LogRetention
}

type LogRetention struct {
	MaxEvents int64
	TTL       time.Duration
}

func DefaultLogRetention() LogRetention {
	return LogRetention{
		MaxEvents: defaultTrafficLogMaxEvents,
		TTL:       defaultTrafficLogTTL,
	}
}

func normalizeLogRetention(retention LogRetention) LogRetention {
	if retention.MaxEvents <= 0 {
		retention.MaxEvents = defaultTrafficLogMaxEvents
	}
	if retention.TTL <= 0 {
		retention.TTL = defaultTrafficLogTTL
	}
	return retention
}

func Connect(uri string, dbName string, retentionOverrides ...LogRetention) (*DB, error) {
	connectCtx, connectCancel := context.WithTimeout(context.Background(), mongoConnectTimeout)
	defer connectCancel()
	clientOptions := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(connectCtx, clientOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	pingCtx, pingCancel := context.WithTimeout(context.Background(), mongoPingTimeout)
	defer pingCancel()
	if err := client.Ping(pingCtx, nil); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	log.Println("Connected to MongoDB successfully")
	retention := DefaultLogRetention()
	if len(retentionOverrides) > 0 {
		retention = normalizeLogRetention(retentionOverrides[0])
	}
	mongoDB := client.Database(dbName)
	database := &DB{
		Client:               client,
		Name:                 dbName,
		Logs:                 mongoDB.Collection("traffic_logs"),
		TrafficConversations: mongoDB.Collection("traffic_conversations"),
		IngestionLogs:        mongoDB.Collection("ingestion_logs"),
		IngestDeadLetters:    mongoDB.Collection("ingest_dead_letters"),
		ScanJobs:             mongoDB.Collection("scan_jobs"),
		ScanResults:          mongoDB.Collection("scan_results"),
		ScanSecrets:          mongoDB.Collection("scan_secrets"),
		AuditLogs:            mongoDB.Collection("audit_logs"),
		Accounts:             mongoDB.Collection("accounts"),
		AccountSettings:      mongoDB.Collection("account_settings"),
		Users:                mongoDB.Collection("users"),
		Sessions:             mongoDB.Collection("sessions"),
		DataSources:          mongoDB.Collection("data_sources"),
		AgentEnrollments:     mongoDB.Collection("agent_enrollments"),
		Agents:               mongoDB.Collection("agents"),
		APIParameters:        mongoDB.Collection("api_parameters"),
		TrafficSamples:       mongoDB.Collection("traffic_samples"),
		SensitiveSamples:     mongoDB.Collection("sensitive_samples"),
		TrafficMetrics:       mongoDB.Collection("traffic_metrics"),
		TrafficMetricEvents:  mongoDB.Collection("traffic_metric_events"),
		LogRetention:         retention,
	}
	indexCtx, indexCancel := context.WithTimeout(context.Background(), mongoIndexTimeout)
	defer indexCancel()
	if err := database.EnsureIndexes(indexCtx); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("failed to create MongoDB indexes: %w", err)
	}
	return database, nil
}

func (db *DB) Disconnect() {
	if err := db.Client.Disconnect(context.Background()); err != nil {
		log.Printf("Error disconnecting from MongoDB: %v\n", err)
	}
}

func (db *DB) EnsureIndexes(ctx context.Context) error {
	retention := normalizeLogRetention(db.LogRetention)
	db.LogRetention = retention

	ttlSeconds := int32(retention.TTL.Seconds())
	if err := createIndexes(ctx, "traffic_logs", db.Logs, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "created_at", Value: 1}},
			Options: options.Index().SetName("traffic_logs_created_at_ttl").SetExpireAfterSeconds(ttlSeconds),
		},
		{
			Keys:    bson.D{{Key: "capture_source", Value: 1}, {Key: "created_at", Value: -1}},
			Options: options.Index().SetName("traffic_logs_capture_source_created_at"),
		},
		{
			Keys:    bson.D{{Key: "agent_id", Value: 1}, {Key: "created_at", Value: -1}},
			Options: options.Index().SetName("traffic_logs_agent_id_created_at"),
		},
		{
			Keys:    bson.D{{Key: "method", Value: 1}, {Key: "host", Value: 1}, {Key: "path", Value: 1}},
			Options: options.Index().SetName("traffic_logs_method_host_path"),
		},
	}); err != nil {
		return err
	}

	if err := createIndexes(ctx, "traffic_conversations", db.TrafficConversations, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "captured_at", Value: 1}},
			Options: options.Index().SetName("traffic_conversations_captured_at_ttl").SetExpireAfterSeconds(ttlSeconds),
		},
		{
			Keys:    bson.D{{Key: "created_at", Value: -1}},
			Options: options.Index().SetName("traffic_conversations_created_at"),
		},
		{
			Keys:    bson.D{{Key: "capture_source", Value: 1}, {Key: "created_at", Value: -1}},
			Options: options.Index().SetName("traffic_conversations_capture_source_created_at"),
		},
		{
			Keys:    bson.D{{Key: "agent_id", Value: 1}, {Key: "created_at", Value: -1}},
			Options: options.Index().SetName("traffic_conversations_agent_id_created_at"),
		},
		{
			Keys:    bson.D{{Key: "method", Value: 1}, {Key: "host", Value: 1}, {Key: "path", Value: 1}},
			Options: options.Index().SetName("traffic_conversations_method_host_path"),
		},
	}); err != nil {
		return err
	}

	if err := createIndexes(ctx, "ingestion_logs", db.IngestionLogs, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "created_at", Value: 1}},
			Options: options.Index().SetName("ingestion_logs_created_at_ttl").SetExpireAfterSeconds(ttlSeconds),
		},
		{
			Keys:    bson.D{{Key: "status", Value: 1}, {Key: "created_at", Value: -1}},
			Options: options.Index().SetName("ingestion_logs_status_created_at"),
		},
	}); err != nil {
		return err
	}

	if err := createIndexes(ctx, "ingest_dead_letters", db.IngestDeadLetters, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "created_at", Value: 1}},
			Options: options.Index().SetName("ingest_dead_letters_created_at_ttl").SetExpireAfterSeconds(ttlSeconds),
		},
		{
			Keys:    bson.D{{Key: "reason", Value: 1}, {Key: "created_at", Value: -1}},
			Options: options.Index().SetName("ingest_dead_letters_reason_created_at"),
		},
	}); err != nil {
		return err
	}

	if err := createIndexes(ctx, "scan_jobs", db.ScanJobs, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "status", Value: 1}, {Key: "created_at", Value: 1}},
			Options: options.Index().SetName("scan_jobs_status_created_at"),
		},
		{
			Keys:    bson.D{{Key: "inventory_id", Value: 1}, {Key: "created_at", Value: -1}},
			Options: options.Index().SetName("scan_jobs_inventory_created_at"),
		},
		{
			Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "created_at", Value: -1}},
			Options: options.Index().SetName("scan_jobs_tenant_created_at"),
		},
	}); err != nil {
		return err
	}

	if err := createIndexes(ctx, "scan_secrets", db.ScanSecrets, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetName("scan_secrets_expires_at_ttl").SetExpireAfterSeconds(0),
		},
		{
			Keys:    bson.D{{Key: "job_id", Value: 1}, {Key: "purpose", Value: 1}},
			Options: options.Index().SetName("scan_secrets_job_purpose"),
		},
	}); err != nil {
		return err
	}

	if err := createIndexes(ctx, "scan_results", db.ScanResults, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "job_id", Value: 1}, {Key: "created_at", Value: -1}},
			Options: options.Index().SetName("scan_results_job_created_at"),
		},
		{
			Keys:    bson.D{{Key: "inventory_id", Value: 1}, {Key: "created_at", Value: -1}},
			Options: options.Index().SetName("scan_results_inventory_created_at"),
		},
		{
			Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "created_at", Value: -1}},
			Options: options.Index().SetName("scan_results_tenant_created_at"),
		},
	}); err != nil {
		return err
	}

	if err := createIndexes(ctx, "api_inventory", db.Client.Database(db.Name).Collection("api_inventory"), []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "updated_at", Value: -1}},
			Options: options.Index().SetName("api_inventory_tenant_updated_at"),
		},
		{
			Keys:    bson.D{{Key: "endpoint_fingerprint", Value: 1}},
			Options: options.Index().SetName("api_inventory_endpoint_fingerprint_unique").SetUnique(true).SetPartialFilterExpression(bson.M{"endpoint_fingerprint": bson.M{"$type": "string"}}),
		},
		{
			Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "method", Value: 1}, {Key: "base_url", Value: 1}, {Key: "path_pattern", Value: 1}},
			Options: options.Index().SetName("api_inventory_tenant_endpoint"),
		},
		{
			Keys:    bson.D{{Key: "capture_source", Value: 1}, {Key: "updated_at", Value: -1}},
			Options: options.Index().SetName("api_inventory_capture_source_updated_at"),
		},
	}); err != nil {
		return err
	}

	if err := createIndexes(ctx, "api_parameters", db.APIParameters, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "endpoint_fingerprint", Value: 1}, {Key: "location", Value: 1}, {Key: "name", Value: 1}},
			Options: options.Index().SetName("api_parameters_endpoint_location_name_unique").SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "location", Value: 1}, {Key: "updated_at", Value: -1}},
			Options: options.Index().SetName("api_parameters_tenant_location_updated_at"),
		},
		{
			Keys:    bson.D{{Key: "sensitive_data", Value: 1}, {Key: "updated_at", Value: -1}},
			Options: options.Index().SetName("api_parameters_sensitive_updated_at"),
		},
	}); err != nil {
		return err
	}

	if err := createIndexes(ctx, "traffic_samples", db.TrafficSamples, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "captured_at", Value: 1}},
			Options: options.Index().SetName("traffic_samples_captured_at_ttl").SetExpireAfterSeconds(ttlSeconds),
		},
		{
			Keys:    bson.D{{Key: "endpoint_fingerprint", Value: 1}, {Key: "captured_at", Value: -1}},
			Options: options.Index().SetName("traffic_samples_endpoint_captured_at"),
		},
		{
			Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "captured_at", Value: -1}},
			Options: options.Index().SetName("traffic_samples_tenant_captured_at"),
		},
	}); err != nil {
		return err
	}

	if err := createIndexes(ctx, "sensitive_samples", db.SensitiveSamples, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "captured_at", Value: 1}},
			Options: options.Index().SetName("sensitive_samples_captured_at_ttl").SetExpireAfterSeconds(ttlSeconds),
		},
		{
			Keys:    bson.D{{Key: "endpoint_fingerprint", Value: 1}, {Key: "captured_at", Value: -1}},
			Options: options.Index().SetName("sensitive_samples_endpoint_captured_at"),
		},
		{
			Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "sensitive_data", Value: 1}, {Key: "captured_at", Value: -1}},
			Options: options.Index().SetName("sensitive_samples_tenant_sensitive_captured_at"),
		},
	}); err != nil {
		return err
	}

	if err := createIndexes(ctx, "traffic_metrics", db.TrafficMetrics, []mongo.IndexModel{
		{
			Keys: bson.D{
				{Key: "tenant_id", Value: 1},
				{Key: "project_id", Value: 1},
				{Key: "endpoint_fingerprint", Value: 1},
				{Key: "bucket_granularity", Value: 1},
				{Key: "bucket_start", Value: 1},
				{Key: "status_code", Value: 1},
				{Key: "auth_observed", Value: 1},
				{Key: "risk_level", Value: 1},
			},
			Options: options.Index().SetName("traffic_metrics_unique_bucket_dimensions").SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "bucket_granularity", Value: 1}, {Key: "bucket_start", Value: -1}},
			Options: options.Index().SetName("traffic_metrics_tenant_bucket"),
		},
		{
			Keys:    bson.D{{Key: "endpoint_fingerprint", Value: 1}, {Key: "bucket_granularity", Value: 1}, {Key: "bucket_start", Value: -1}},
			Options: options.Index().SetName("traffic_metrics_endpoint_bucket"),
		},
		{
			Keys:    bson.D{{Key: "tenant_id", Value: 1}, {Key: "status_class", Value: 1}, {Key: "bucket_start", Value: -1}},
			Options: options.Index().SetName("traffic_metrics_tenant_status_bucket"),
		},
	}); err != nil {
		return err
	}

	if err := createIndexes(ctx, "traffic_metric_events", db.TrafficMetricEvents, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "event_key", Value: 1}},
			Options: options.Index().SetName("traffic_metric_events_event_key_unique").SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "created_at", Value: 1}},
			Options: options.Index().SetName("traffic_metric_events_created_at_ttl").SetExpireAfterSeconds(ttlSeconds),
		},
		{
			Keys:    bson.D{{Key: "endpoint_fingerprint", Value: 1}, {Key: "bucket_start", Value: -1}},
			Options: options.Index().SetName("traffic_metric_events_endpoint_bucket"),
		},
	}); err != nil {
		return err
	}

	if err := createIndexes(ctx, "audit_logs", db.AuditLogs, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "created_at", Value: -1}},
			Options: options.Index().SetName("audit_logs_created_at"),
		},
		{
			Keys:    bson.D{{Key: "actor_id", Value: 1}, {Key: "created_at", Value: -1}},
			Options: options.Index().SetName("audit_logs_actor_created_at"),
		},
		{
			Keys:    bson.D{{Key: "action", Value: 1}, {Key: "created_at", Value: -1}},
			Options: options.Index().SetName("audit_logs_action_created_at"),
		},
	}); err != nil {
		return err
	}

	if err := createIndexes(ctx, "accounts", db.Accounts, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "slug", Value: 1}},
			Options: options.Index().SetName("accounts_slug_unique").SetUnique(true),
		},
	}); err != nil {
		return err
	}

	if err := createIndexes(ctx, "account_settings", db.AccountSettings, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "account_id", Value: 1}},
			Options: options.Index().SetName("account_settings_account_unique").SetUnique(true),
		},
	}); err != nil {
		return err
	}

	if err := createIndexes(ctx, "users", db.Users, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "email", Value: 1}},
			Options: options.Index().SetName("users_email_unique").SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "account_id", Value: 1}, {Key: "role", Value: 1}},
			Options: options.Index().SetName("users_account_role"),
		},
	}); err != nil {
		return err
	}

	if err := createIndexes(ctx, "sessions", db.Sessions, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "access_token_hash", Value: 1}},
			Options: options.Index().SetName("sessions_access_token_hash_unique").SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "refresh_token_hash", Value: 1}},
			Options: options.Index().SetName("sessions_refresh_token_hash_unique").SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "refresh_expires_at", Value: 1}},
			Options: options.Index().SetName("sessions_refresh_expires_at_ttl").SetExpireAfterSeconds(0),
		},
		{
			Keys:    bson.D{{Key: "user_id", Value: 1}, {Key: "created_at", Value: -1}},
			Options: options.Index().SetName("sessions_user_created_at"),
		},
	}); err != nil {
		return err
	}

	if err := createIndexes(ctx, "data_sources", db.DataSources, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "account_id", Value: 1}, {Key: "created_at", Value: -1}},
			Options: options.Index().SetName("data_sources_account_created_at"),
		},
		{
			Keys:    bson.D{{Key: "account_id", Value: 1}, {Key: "status", Value: 1}, {Key: "deleted_at", Value: 1}},
			Options: options.Index().SetName("data_sources_account_status_deleted"),
		},
		{
			Keys:    bson.D{{Key: "account_id", Value: 1}, {Key: "type", Value: 1}},
			Options: options.Index().SetName("data_sources_account_type"),
		},
	}); err != nil {
		return err
	}

	if err := createIndexes(ctx, "agent_enrollments", db.AgentEnrollments, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "token_hash", Value: 1}},
			Options: options.Index().SetName("agent_enrollments_token_hash_unique").SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetName("agent_enrollments_expires_at_ttl").SetExpireAfterSeconds(0),
		},
		{
			Keys:    bson.D{{Key: "account_id", Value: 1}, {Key: "created_at", Value: -1}},
			Options: options.Index().SetName("agent_enrollments_account_created_at"),
		},
	}); err != nil {
		return err
	}

	return createIndexes(ctx, "agents", db.Agents, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "token_hash", Value: 1}},
			Options: options.Index().SetName("agents_token_hash_unique").SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "account_id", Value: 1}, {Key: "status", Value: 1}},
			Options: options.Index().SetName("agents_account_status"),
		},
		{
			Keys:    bson.D{{Key: "data_source_id", Value: 1}, {Key: "created_at", Value: -1}},
			Options: options.Index().SetName("agents_data_source_created_at"),
		},
	})
}

func createIndexes(ctx context.Context, collectionName string, collection *mongo.Collection, indexes []mongo.IndexModel) error {
	if collection == nil || len(indexes) == 0 {
		return nil
	}
	_, err := collection.Indexes().CreateMany(ctx, indexes)
	if err != nil {
		return fmt.Errorf("%s indexes: %w", collectionName, err)
	}
	return nil
}
