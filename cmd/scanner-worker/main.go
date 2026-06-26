package main

import (
	"context"
	"errors"
	"flag"
	"karaxys_backend/internal/config"
	"karaxys_backend/internal/coordination"
	"karaxys_backend/internal/core"
	"karaxys_backend/internal/db"
	"karaxys_backend/internal/scancontrol"
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
	redisRuntime, err := coordination.NewRedisRuntimeFromEnv()
	if err != nil {
		if config.IsProduction() {
			log.Fatalf("Redis/Valkey scan coordination is required in production: %v", err)
		}
		log.Printf("Redis/Valkey scan coordination disabled: %v", err)
	}
	if redisRuntime != nil {
		defer redisRuntime.Close()
		log.Printf("Redis/Valkey scanner coordination enabled prefix=%s", redisRuntime.KeyPrefix)
	}
	scanLimits := scancontrol.LoadConfigFromEnv().Normalize()
	log.Printf("Scanner limits global_concurrency=%d target_jobs_per_window=%d target_rate_window=%s capacity_retry_delay=%s nuclei_rate_limit_per_second=%d template_concurrency=%d host_concurrency=%d payload_concurrency=%d probe_concurrency=%d",
		scanLimits.GlobalConcurrency,
		scanLimits.TargetJobsPerWindow,
		scanLimits.TargetRateWindow,
		scanLimits.CapacityRetryDelay,
		scanLimits.NucleiRateLimitPerSecond,
		scanLimits.NucleiTemplateConcurrency,
		scanLimits.NucleiHostConcurrency,
		scanLimits.NucleiPayloadConcurrency,
		scanLimits.NucleiProbeConcurrency,
	)
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

		processed, err := processOne(database, engine, *workerID, redisRuntime, scanLimits)
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

func processOne(database *db.DB, engine *scanner.Scanner, workerID string, redisRuntime *coordination.RedisRuntime, scanLimits scancontrol.Config) (bool, error) {
	job, err := database.ClaimNextScanJob(workerID)
	if err != nil || job == nil {
		return false, err
	}

	log.Printf("Claimed scan job id=%s test=%s inventory=%s", job.ID.Hex(), job.TestType, job.InventoryID.Hex())
	var lock coordination.DistributedLock
	if redisRuntime != nil && redisRuntime.Locker != nil {
		lockValue := workerID + ":" + primitive.NewObjectID().Hex()
		acquiredLock, acquired, lockErr := redisRuntime.Locker.TryLock(context.Background(), coordination.ScanJobLockKey(job.ID.Hex()), lockValue, redisRuntime.ScanLockTTL)
		if lockErr != nil {
			message := "scan coordination lock unavailable"
			_ = database.RequeueScanJob(job.ID, message+": "+lockErr.Error(), scanLimits.CapacityRetryDelay)
			setScanProgress(redisRuntime, job.ID.Hex(), core.ScanJobStatusQueued, workerID, message, 0)
			return true, lockErr
		}
		if !acquired {
			message := "scan coordination lock already held"
			_ = database.RequeueScanJob(job.ID, message, scanLimits.CapacityRetryDelay)
			setScanProgress(redisRuntime, job.ID.Hex(), core.ScanJobStatusQueued, workerID, message, 0)
			return true, nil
		}
		lock = acquiredLock
		defer func() {
			if err := lock.Release(context.Background()); err != nil {
				log.Printf("Failed to release scan lock job=%s: %v", job.ID.Hex(), err)
			}
		}()
	}

	config := job.Config
	cancelled, err := scanJobCancelled(database, job.ID)
	if err != nil {
		return true, err
	}
	if cancelled {
		cleanupScanSecret(database, job.Config.AuthSecretRef)
		setScanProgress(redisRuntime, job.ID.Hex(), core.ScanJobStatusCancelled, workerID, "scan cancelled", 0)
		return true, nil
	}
	admission, admitted, admissionMessage, retryDelay, err := acquireScanAdmission(redisRuntime, *job, workerID, scanLimits)
	if err != nil {
		if admissionMessage == "invalid scan target" {
			_ = database.FailScanJob(job.ID, admissionMessage+": "+err.Error())
			cleanupScanSecret(database, job.Config.AuthSecretRef)
			setScanProgress(redisRuntime, job.ID.Hex(), core.ScanJobStatusFailed, workerID, admissionMessage, 0)
			return true, err
		}
		_ = database.RequeueScanJob(job.ID, admissionMessage+": "+err.Error(), retryDelay)
		setScanProgress(redisRuntime, job.ID.Hex(), core.ScanJobStatusQueued, workerID, admissionMessage, 0)
		return true, err
	}
	if !admitted {
		_ = database.RequeueScanJob(job.ID, admissionMessage, retryDelay)
		setScanProgress(redisRuntime, job.ID.Hex(), core.ScanJobStatusQueued, workerID, admissionMessage, 0)
		return true, nil
	}
	defer admission.Release()
	setScanProgress(redisRuntime, job.ID.Hex(), core.ScanJobStatusRunning, workerID, "", 0)

	if err := hydrateScanAuthSecret(database, &config); err != nil {
		_ = database.FailScanJob(job.ID, err.Error())
		cleanupScanSecret(database, job.Config.AuthSecretRef)
		setScanProgress(redisRuntime, job.ID.Hex(), core.ScanJobStatusFailed, workerID, err.Error(), 0)
		return true, err
	}
	defer cleanupScanSecret(database, job.Config.AuthSecretRef)

	timeout := time.Duration(job.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = time.Duration(core.DefaultScanTimeoutSeconds) * time.Second
	}
	scanCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	results, err := engine.ExecuteScanContext(scanCtx, config)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(scanCtx.Err(), context.DeadlineExceeded) {
			message := "scan timed out"
			_ = database.TimeoutScanJob(job.ID, message)
			setScanProgress(redisRuntime, job.ID.Hex(), core.ScanJobStatusTimedOut, workerID, message, 0)
			return true, err
		}
		_ = database.FailScanJob(job.ID, err.Error())
		setScanProgress(redisRuntime, job.ID.Hex(), core.ScanJobStatusFailed, workerID, err.Error(), 0)
		return true, err
	}
	cancelled, err = scanJobCancelled(database, job.ID)
	if err != nil {
		return true, err
	}
	if cancelled {
		setScanProgress(redisRuntime, job.ID.Hex(), core.ScanJobStatusCancelled, workerID, "scan cancelled", 0)
		return true, nil
	}

	for _, res := range results {
		cancelled, err = scanJobCancelled(database, job.ID)
		if err != nil {
			return true, err
		}
		if cancelled {
			setScanProgress(redisRuntime, job.ID.Hex(), core.ScanJobStatusCancelled, workerID, "scan cancelled", 0)
			return true, nil
		}
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
			setScanProgress(redisRuntime, job.ID.Hex(), core.ScanJobStatusFailed, workerID, err.Error(), len(results))
			return true, err
		}
	}

	if err := database.CompleteScanJob(job.ID, len(results)); err != nil {
		setScanProgress(redisRuntime, job.ID.Hex(), core.ScanJobStatusFailed, workerID, err.Error(), len(results))
		return true, err
	}
	setScanProgress(redisRuntime, job.ID.Hex(), core.ScanJobStatusCompleted, workerID, "", len(results))
	log.Printf("Completed scan job id=%s results=%d", job.ID.Hex(), len(results))
	return true, nil
}

type scanAdmission struct {
	locks []coordination.DistributedLock
}

func (a *scanAdmission) Release() {
	if a == nil {
		return
	}
	for i := len(a.locks) - 1; i >= 0; i-- {
		if err := a.locks[i].Release(context.Background()); err != nil {
			log.Printf("Failed to release scanner admission lock: %v", err)
		}
	}
}

func acquireScanAdmission(redisRuntime *coordination.RedisRuntime, job core.ScanJob, workerID string, limits scancontrol.Config) (*scanAdmission, bool, string, time.Duration, error) {
	limits = limits.Normalize()
	admission := &scanAdmission{}
	if redisRuntime == nil {
		return admission, true, "", 0, nil
	}
	value := workerID + ":" + job.ID.Hex() + ":" + primitive.NewObjectID().Hex()
	if redisRuntime.Semaphore != nil {
		lock, acquired, err := redisRuntime.Semaphore.TryAcquire(context.Background(), coordination.ScannerGlobalSemaphoreKey(), value, limits.GlobalConcurrency, limits.AdmissionLease)
		if err != nil {
			return admission, false, "scanner global concurrency unavailable", limits.CapacityRetryDelay, err
		}
		if !acquired {
			return admission, false, "scanner global concurrency limit reached", limits.CapacityRetryDelay, nil
		}
		admission.locks = append(admission.locks, lock)
	}
	if limits.TargetJobsPerWindow > 0 && redisRuntime.RateLimiter != nil {
		targetKey, err := scancontrol.TargetRateKey(job)
		if err != nil {
			admission.Release()
			return admission, false, "invalid scan target", 0, err
		}
		allowed, err := redisRuntime.RateLimiter.Allow(context.Background(), targetKey, limits.TargetJobsPerWindow, limits.TargetRateWindow)
		if err != nil {
			admission.Release()
			return admission, false, "scanner target rate limiter unavailable", limits.CapacityRetryDelay, err
		}
		if !allowed {
			admission.Release()
			return admission, false, "scanner target rate limit reached", limits.TargetRateWindow, nil
		}
	}
	return admission, true, "", 0, nil
}

func scanJobCancelled(database *db.DB, jobID primitive.ObjectID) (bool, error) {
	job, err := database.GetScanJob(jobID)
	if err != nil {
		return false, err
	}
	return job.Status == core.ScanJobStatusCancelled, nil
}

func setScanProgress(redisRuntime *coordination.RedisRuntime, jobID string, status string, workerID string, message string, resultsCount int) {
	if redisRuntime == nil || redisRuntime.Progress == nil {
		return
	}
	if err := redisRuntime.Progress.Set(context.Background(), coordination.ScanProgress{
		JobID:        jobID,
		Status:       status,
		WorkerID:     workerID,
		Message:      message,
		ResultsCount: resultsCount,
		UpdatedAt:    time.Now().UTC(),
	}, redisRuntime.ProgressTTL); err != nil {
		log.Printf("Failed to update scan progress job=%s status=%s: %v", jobID, status, err)
	}
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
