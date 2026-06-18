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
	}); err != nil {
		return err
	}

	return createIndexes(ctx, "audit_logs", db.AuditLogs, []mongo.IndexModel{
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
