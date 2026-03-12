package db

import(
	"context"
	"fmt"
	"log"
	"time"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type DB struct {
	Client *mongo.Client
	Name   string
	Logs   *mongo.Collection
}

func Connect(uri string, dbName string) (*DB, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	clientOptions := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	log.Println("Connected to MongoDB successfully")
	return &DB{
		Client: client,
		Name:   dbName,
		Logs:   client.Database(dbName).Collection("traffic_logs"),
	}, nil
}

func (db *DB) Disconnect() {
	if err := db.Client.Disconnect(context.Background()); err != nil {
		log.Printf("Error disconnecting from MongoDB: %v\n", err)
	}
}