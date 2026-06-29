package db

import (
	"context"
	"errors"
	"time"

	"karaxys_backend/internal/core"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	ErrDataSourceNotFound    = errors.New("data source not found")
	ErrEnrollmentNotFound    = errors.New("agent enrollment token is invalid or expired")
	ErrEnrollmentAlreadyUsed = errors.New("agent enrollment token has already been used")
	ErrAgentNotFound         = errors.New("agent not found")
)

func (db *DB) CreateDataSource(source core.DataSource) (core.DataSource, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()
	if source.ID.IsZero() {
		source.ID = primitive.NewObjectID()
	}
	if source.Status == "" {
		source.Status = core.DataSourceStatusPending
	}
	if source.CreatedAt.IsZero() {
		source.CreatedAt = now
	}
	source.UpdatedAt = now
	if _, err := db.DataSources.InsertOne(ctx, source); err != nil {
		return core.DataSource{}, err
	}
	return source, nil
}

func (db *DB) ListDataSources(accountID primitive.ObjectID) ([]core.DataSource, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	filter := bson.M{"account_id": accountID, "deleted_at": zeroOrMissingTimeFilter()}
	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}})
	cursor, err := db.DataSources.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var sources []core.DataSource
	if err := cursor.All(ctx, &sources); err != nil {
		return nil, err
	}
	return sources, nil
}

func (db *DB) GetDataSourceForAccount(accountID primitive.ObjectID, sourceID primitive.ObjectID) (core.DataSource, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var source core.DataSource
	err := db.DataSources.FindOne(ctx, bson.M{"_id": sourceID, "account_id": accountID, "deleted_at": zeroOrMissingTimeFilter()}).Decode(&source)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return core.DataSource{}, ErrDataSourceNotFound
	}
	return source, err
}

func (db *DB) DeleteDataSourceForAccount(accountID primitive.ObjectID, sourceID primitive.ObjectID, deletedBy primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	now := time.Now().UTC()
	set := bson.M{
		"status":     core.DataSourceStatusDeleted,
		"deleted_at": now,
		"updated_at": now,
	}
	if !deletedBy.IsZero() {
		set["deleted_by"] = deletedBy
	}
	result, err := db.DataSources.UpdateOne(ctx, bson.M{
		"_id":        sourceID,
		"account_id": accountID,
	}, bson.M{"$set": set})
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return ErrDataSourceNotFound
	}
	if _, err := db.AgentEnrollments.UpdateMany(ctx, bson.M{
		"account_id":     accountID,
		"data_source_id": sourceID,
		"used_at":        zeroOrMissingTimeFilter(),
	}, bson.M{"$set": bson.M{
		"expires_at": now,
	}}); err != nil {
		return err
	}
	if _, err := db.Agents.UpdateMany(ctx, bson.M{
		"account_id":     accountID,
		"data_source_id": sourceID,
		"status":         "active",
	}, bson.M{"$set": bson.M{
		"status":     "disabled",
		"updated_at": now,
	}}); err != nil {
		return err
	}
	return nil
}

func (db *DB) CreateAgentEnrollment(enrollment core.AgentEnrollment) (core.AgentEnrollment, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if enrollment.ID.IsZero() {
		enrollment.ID = primitive.NewObjectID()
	}
	if enrollment.CreatedAt.IsZero() {
		enrollment.CreatedAt = time.Now().UTC()
	}
	if _, err := db.AgentEnrollments.InsertOne(ctx, enrollment); err != nil {
		return core.AgentEnrollment{}, err
	}
	return enrollment, nil
}

func (db *DB) RegisterAgentFromEnrollment(tokenHash string, agentName string, agentTokenHash string) (core.Agent, core.AgentEnrollment, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	now := time.Now().UTC()
	agentID := primitive.NewObjectID()

	filter := bson.M{
		"token_hash": tokenHash,
		"expires_at": bson.M{"$gt": now},
		"used_at":    zeroOrMissingTimeFilter(),
	}
	update := bson.M{"$set": bson.M{
		"used_at":             now,
		"registered_agent_id": agentID,
	}}
	opts := options.FindOneAndUpdate().SetReturnDocument(options.After)
	var enrollment core.AgentEnrollment
	err := db.AgentEnrollments.FindOneAndUpdate(ctx, filter, update, opts).Decode(&enrollment)
	if errors.Is(err, mongo.ErrNoDocuments) {
		var existing core.AgentEnrollment
		existingErr := db.AgentEnrollments.FindOne(ctx, bson.M{"token_hash": tokenHash}).Decode(&existing)
		if existingErr == nil && !existing.UsedAt.IsZero() {
			return core.Agent{}, core.AgentEnrollment{}, ErrEnrollmentAlreadyUsed
		}
		return core.Agent{}, core.AgentEnrollment{}, ErrEnrollmentNotFound
	}
	if err != nil {
		return core.Agent{}, core.AgentEnrollment{}, err
	}

	if agentName == "" {
		agentName = enrollment.Name
	}
	if agentName == "" {
		agentName = "Karaxys eBPF agent"
	}
	agent := core.Agent{
		ID:           agentID,
		AccountID:    enrollment.AccountID,
		DataSourceID: enrollment.DataSourceID,
		Name:         agentName,
		TokenHash:    agentTokenHash,
		Status:       "active",
		CreatedAt:    now,
		UpdatedAt:    now,
		LastSeenAt:   now,
	}
	if _, err := db.Agents.InsertOne(ctx, agent); err != nil {
		return core.Agent{}, core.AgentEnrollment{}, err
	}
	_, _ = db.DataSources.UpdateOne(ctx, bson.M{"_id": enrollment.DataSourceID}, bson.M{"$set": bson.M{
		"status":     core.DataSourceStatusConnected,
		"updated_at": now,
	}})
	return agent, enrollment, nil
}

func (db *DB) FindAgentByTokenHash(tokenHash string) (core.Agent, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var agent core.Agent
	err := db.Agents.FindOne(ctx, bson.M{"token_hash": tokenHash, "status": "active"}).Decode(&agent)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return core.Agent{}, ErrAgentNotFound
	}
	return agent, err
}

func (db *DB) MarkAgentSeen(agentID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()
	_, err := db.Agents.UpdateByID(ctx, agentID, bson.M{"$set": bson.M{
		"last_seen_at": now,
		"updated_at":   now,
	}})
	return err
}

func (db *DB) ListAgentsForAccount(accountID primitive.ObjectID) ([]core.Agent, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	opts := options.Find().SetSort(bson.D{{Key: "last_seen_at", Value: -1}}).SetLimit(100)
	cursor, err := db.Agents.Find(ctx, bson.M{"account_id": accountID}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var agents []core.Agent
	if err := cursor.All(ctx, &agents); err != nil {
		return nil, err
	}
	return agents, nil
}

// MarkIngestTrafficSeen updates last_traffic_seen_at and ensures status=connected on
// the most recently created non-deleted data source for the account. If no data source
// exists it auto-creates a default EBPF_LINUX one so the dashboard shows activity
// immediately without requiring manual setup first.
func (db *DB) MarkIngestTrafficSeen(ctx context.Context, accountID primitive.ObjectID) error {
	now := time.Now().UTC()

	// Try to update an existing non-deleted data source (prefer pending → connected promotion).
	filter := bson.M{
		"account_id": accountID,
		"deleted_at": zeroOrMissingTimeFilter(),
	}
	update := bson.M{"$set": bson.M{
		"status":               core.DataSourceStatusConnected,
		"last_traffic_seen_at": now,
		"updated_at":           now,
	}}
	opts := options.FindOneAndUpdate().
		SetSort(bson.D{{Key: "created_at", Value: -1}}).
		SetReturnDocument(options.After)

	var updated core.DataSource
	err := db.DataSources.FindOneAndUpdate(ctx, filter, update, opts).Decode(&updated)
	if err == nil {
		return nil
	}
	if !errors.Is(err, mongo.ErrNoDocuments) {
		return err
	}

	// No data source yet — auto-create a default one so the UI shows activity.
	source := core.DataSource{
		ID:                primitive.NewObjectID(),
		AccountID:         accountID,
		Type:              core.DataSourceTypeEBPFLinux,
		ConnectorType:     core.DataSourceConnectorEBPFDocker,
		Name:              "eBPF Agent",
		Status:            core.DataSourceStatusConnected,
		LastTrafficSeenAt: now,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	_, err = db.DataSources.InsertOne(ctx, source)
	return err
}

func (db *DB) ListEnrollmentsForAccount(accountID primitive.ObjectID) ([]core.AgentEnrollment, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	filter := bson.M{
		"account_id": accountID,
		"expires_at": bson.M{"$gt": time.Now().UTC()},
		"used_at":    bson.M{"$exists": false},
	}
	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}).SetLimit(50)
	cursor, err := db.AgentEnrollments.Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var enrollments []core.AgentEnrollment
	if err := cursor.All(ctx, &enrollments); err != nil {
		return nil, err
	}
	return enrollments, nil
}
