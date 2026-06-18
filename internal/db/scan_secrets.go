package db

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"karaxys_backend/internal/core"
)

const defaultScanSecretTTL = 24 * time.Hour

func (db *DB) SaveScanSecret(secret core.ScanSecret) (core.ScanSecret, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now().UTC()
	if secret.ID.IsZero() {
		secret.ID = primitive.NewObjectID()
	}
	if secret.CreatedAt.IsZero() {
		secret.CreatedAt = now
	}
	if secret.ExpiresAt.IsZero() {
		secret.ExpiresAt = now.Add(defaultScanSecretTTL)
	}
	if secret.Purpose == "" {
		secret.Purpose = core.ScanSecretPurposeAuth
	}

	_, err := db.ScanSecrets.InsertOne(ctx, secret)
	return secret, err
}

func (db *DB) GetScanSecret(id primitive.ObjectID) (*core.ScanSecret, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var secret core.ScanSecret
	if err := db.ScanSecrets.FindOne(ctx, bson.M{"_id": id}).Decode(&secret); err != nil {
		return nil, err
	}
	if !secret.ExpiresAt.IsZero() && time.Now().UTC().After(secret.ExpiresAt) {
		return nil, mongo.ErrNoDocuments
	}
	return &secret, nil
}

func (db *DB) DeleteScanSecret(id primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := db.ScanSecrets.DeleteOne(ctx, bson.M{"_id": id})
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil
	}
	return err
}
