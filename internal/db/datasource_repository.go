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
	filter := bson.M{"account_id": accountID}
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
	err := db.DataSources.FindOne(ctx, bson.M{"_id": sourceID, "account_id": accountID}).Decode(&source)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return core.DataSource{}, ErrDataSourceNotFound
	}
	return source, err
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
