package db
import(
	"context"
	"log"
	"time"
	"vuln_scanner/internal/core"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func (db *DB) SaveLog(logEntry core.TrafficLog) error{
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	logEntry.ID = primitive.NewObjectID()
	logEntry.CreatedAt = time.Now()
	logEntry.IsScanned = false
	_, err := db.Logs.InsertOne(ctx, logEntry)
	if err != nil{
		log.Printf("Failed to save log entry: %v\n", err)
		return err
	}
	return nil
}