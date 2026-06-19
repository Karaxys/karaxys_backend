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

const (
	defaultAccountRetentionHours   = 24
	defaultAccountMaxTrafficEvents = 1000
)

func (db *DB) GetOrCreateAccountSettings(accountID primitive.ObjectID) (core.AccountSettings, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var settings core.AccountSettings
	err := db.AccountSettings.FindOne(ctx, bson.M{"account_id": accountID}).Decode(&settings)
	if err == nil {
		return settings, nil
	}
	if !errors.Is(err, mongo.ErrNoDocuments) {
		return core.AccountSettings{}, err
	}

	now := time.Now().UTC()
	settings = core.AccountSettings{
		ID:               primitive.NewObjectID(),
		AccountID:        accountID,
		RetentionHours:   defaultAccountRetentionHours,
		MaxTrafficEvents: defaultAccountMaxTrafficEvents,
		RedactionEnabled: true,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if _, err := db.AccountSettings.InsertOne(ctx, settings); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			err = db.AccountSettings.FindOne(ctx, bson.M{"account_id": accountID}).Decode(&settings)
			return settings, err
		}
		return core.AccountSettings{}, err
	}
	return settings, nil
}

func (db *DB) UpdateAccountSettings(accountID primitive.ObjectID, updatedBy primitive.ObjectID, retentionHours int, maxTrafficEvents int) (core.AccountSettings, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()
	set := bson.M{
		"retention_hours":    retentionHours,
		"max_traffic_events": maxTrafficEvents,
		"redaction_enabled":  true,
		"updated_at":         now,
	}
	if !updatedBy.IsZero() {
		set["updated_by"] = updatedBy
	}
	update := bson.M{
		"$set": set,
		"$setOnInsert": bson.M{
			"_id":        primitive.NewObjectID(),
			"account_id": accountID,
			"created_at": now,
		},
	}
	opts := options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After)
	var settings core.AccountSettings
	err := db.AccountSettings.FindOneAndUpdate(ctx, bson.M{"account_id": accountID}, update, opts).Decode(&settings)
	return settings, err
}
