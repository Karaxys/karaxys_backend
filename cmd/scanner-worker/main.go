package main

import (
	"flag"
	"karaxys_backend/internal/config"
	"karaxys_backend/internal/core"
	"karaxys_backend/internal/db"
	"karaxys_backend/internal/scanner"
	"karaxys_backend/internal/security/scansecrets"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

func main() {
	workerID := flag.String("worker-id", hostnameDefault("karaxys-scanner-worker"), "Scanner worker instance id")
	pollInterval := flag.Duration("poll-interval", 2*time.Second, "Scan job polling interval")
	once := flag.Bool("once", false, "Process at most one scan job and exit")
	flag.Parse()

	cfg, err := config.LoadDatabaseConfig()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}
	if err := config.ValidateProductionEnvironment(config.ServiceScannerWorker); err != nil {
		log.Fatalf("Invalid production environment: %v", err)
	}
	database, err := db.Connect(cfg.MongoURI, cfg.MongoDBName, db.LogRetention{
		MaxEvents: cfg.TrafficLogMaxEvents,
		TTL:       cfg.TrafficLogTTL,
	})
	if err != nil {
		log.Fatalf("Error connecting to DB: %v", err)
	}
	defer database.Disconnect()

	engine := scanner.NewScanner()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)

	log.Printf("Scanner worker started. worker_id=%s poll_interval=%s", *workerID, *pollInterval)
	for {
		select {
		case sig := <-stop:
			log.Printf("Caught signal %v: terminating scanner worker", sig)
			return
		default:
		}

		processed, err := processOne(database, engine, *workerID)
		if err != nil {
			log.Printf("Scanner worker error: %v", err)
		}
		if *once {
			return
		}
		if !processed {
			time.Sleep(*pollInterval)
		}
	}
}

func processOne(database *db.DB, engine *scanner.Scanner, workerID string) (bool, error) {
	job, err := database.ClaimNextScanJob(workerID)
	if err != nil || job == nil {
		return false, err
	}

	log.Printf("Claimed scan job id=%s test=%s inventory=%s", job.ID.Hex(), job.TestType, job.InventoryID.Hex())
	defer cleanupScanSecret(database, job.Config.AuthSecretRef)

	config := job.Config
	if err := hydrateScanAuthSecret(database, &config); err != nil {
		_ = database.FailScanJob(job.ID, err.Error())
		return true, err
	}

	results, err := engine.ExecuteScan(config)
	if err != nil {
		_ = database.FailScanJob(job.ID, err.Error())
		return true, err
	}

	for _, res := range results {
		if err := database.SaveScanResult(core.ScanResult{
			TenantID:       job.TenantID,
			ProjectID:      job.ProjectID,
			JobID:          job.ID,
			SchemaVersion:  res.SchemaVersion,
			InventoryID:    job.InventoryID,
			TestType:       res.TestType,
			Vulnerable:     res.Vulnerable,
			Severity:       res.Severity,
			Description:    res.Description,
			Proof:          res.Proof,
			ResponseStatus: res.ResponseStatus,
			ResponseBody:   res.ResponseBody,
			CreatedAt:      time.Now().UTC(),
		}); err != nil {
			_ = database.FailScanJob(job.ID, err.Error())
			return true, err
		}
	}

	if err := database.CompleteScanJob(job.ID, len(results)); err != nil {
		return true, err
	}
	log.Printf("Completed scan job id=%s results=%d", job.ID.Hex(), len(results))
	return true, nil
}

func hydrateScanAuthSecret(database *db.DB, config *core.ScanConfig) error {
	if config == nil || config.AuthSecretRef == "" {
		return nil
	}
	secretID, err := primitive.ObjectIDFromHex(config.AuthSecretRef)
	if err != nil {
		return err
	}
	secret, err := database.GetScanSecret(secretID)
	if err != nil {
		return err
	}
	protector, err := scansecrets.FromEnv()
	if err != nil {
		return err
	}
	plaintext, err := protector.Decrypt(secret.Nonce, secret.Ciphertext)
	if err != nil {
		return err
	}
	config.ManualAuth = plaintext
	return nil
}

func cleanupScanSecret(database *db.DB, ref string) {
	if ref == "" {
		return
	}
	secretID, err := primitive.ObjectIDFromHex(ref)
	if err != nil {
		log.Printf("Invalid scan secret ref=%s: %v", ref, err)
		return
	}
	if err := database.DeleteScanSecret(secretID); err != nil {
		log.Printf("Failed to cleanup scan secret ref=%s: %v", ref, err)
	}
}

func hostnameDefault(fallback string) string {
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		return hostname
	}
	return fallback
}
