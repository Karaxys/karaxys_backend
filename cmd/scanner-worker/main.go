package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"karaxys_backend/cmd/scanner-worker/internal/nucleiscanner"
	"karaxys_backend/internal/config"
	"karaxys_backend/internal/coordination"
	"karaxys_backend/internal/core"
	"karaxys_backend/internal/db"
	"karaxys_backend/internal/queue"
	"karaxys_backend/internal/scancontrol"
	"karaxys_backend/internal/scanner"
	"karaxys_backend/internal/security/scansecrets"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
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

	engine := nucleiscanner.New(scanner.DefaultTemplateRegistry())
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
	queueConsumer, err := newScannerQueueConsumer()
	if err != nil {
		if config.IsProduction() {
			log.Fatalf("Scanner queue consumer is required in production: %v", err)
		}
		log.Printf("Scanner queue consumer disabled: %v", err)
	}
	if queueConsumer != nil {
		defer queueConsumer.Close()
		log.Printf("Scanner queue consumer enabled topic=%s", queue.TopicScanJobs)
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

		processed := false
		if queueConsumer != nil {
			consumeCtx, cancel := context.WithTimeout(context.Background(), *pollInterval)
			processed, err = processQueuedScanJob(consumeCtx, queueConsumer, database, engine, *workerID, redisRuntime, scanLimits)
			cancel()
			if err != nil {
				log.Printf("Scanner queue worker error: %v", err)
			}
		}
		if !processed {
			processed, err = processOne(database, engine, *workerID, redisRuntime, scanLimits)
		}
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

func processOne(database *db.DB, engine scanner.Executor, workerID string, redisRuntime *coordination.RedisRuntime, scanLimits scancontrol.Config) (bool, error) {
	job, err := database.ClaimNextScanJob(workerID)
	if err != nil || job == nil {
		return false, err
	}
	return processClaimedJob(database, engine, workerID, redisRuntime, scanLimits, job)
}

func processClaimedJob(database *db.DB, engine scanner.Executor, workerID string, redisRuntime *coordination.RedisRuntime, scanLimits scancontrol.Config, job *core.ScanJob) (bool, error) {
	log.Printf("Claimed scan job id=%s test=%s inventory=%s", job.ID.Hex(), job.TestType, job.InventoryID.Hex())
	var lock coordination.DistributedLock
	if redisRuntime != nil && redisRuntime.Locker != nil {
		lockValue := workerID + ":" + primitive.NewObjectID().Hex()
		acquiredLock, acquired, lockErr := redisRuntime.Locker.TryLock(context.Background(), coordination.ScanJobLockKey(job.ID.Hex()), lockValue, redisRuntime.ScanLockTTL)
		if lockErr != nil {
			message := "scan coordination lock unavailable"
			_ = database.RequeueScanJob(job.ID, message+": "+lockErr.Error(), scanLimits.CapacityRetryDelay)
			setScanProgress(database, redisRuntime, job, core.ScanJobStatusQueued, workerID, message, 0)
			return true, lockErr
		}
		if !acquired {
			message := "scan coordination lock already held"
			_ = database.RequeueScanJob(job.ID, message, scanLimits.CapacityRetryDelay)
			setScanProgress(database, redisRuntime, job, core.ScanJobStatusQueued, workerID, message, 0)
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
		setScanProgress(database, redisRuntime, job, core.ScanJobStatusCancelled, workerID, "scan cancelled", 0)
		return true, nil
	}
	admission, admitted, admissionMessage, retryDelay, err := acquireScanAdmission(redisRuntime, *job, workerID, scanLimits)
	if err != nil {
		if admissionMessage == "invalid scan target" {
			_ = database.FailScanJob(job.ID, admissionMessage+": "+err.Error())
			cleanupScanSecret(database, job.Config.AuthSecretRef)
			setScanProgress(database, redisRuntime, job, core.ScanJobStatusFailed, workerID, admissionMessage, 0)
			return true, err
		}
		_ = database.RequeueScanJob(job.ID, admissionMessage+": "+err.Error(), retryDelay)
		setScanProgress(database, redisRuntime, job, core.ScanJobStatusQueued, workerID, admissionMessage, 0)
		return true, err
	}
	if !admitted {
		_ = database.RequeueScanJob(job.ID, admissionMessage, retryDelay)
		setScanProgress(database, redisRuntime, job, core.ScanJobStatusQueued, workerID, admissionMessage, 0)
		return true, nil
	}
	defer admission.Release()
	setScanProgress(database, redisRuntime, job, core.ScanJobStatusRunning, workerID, "", 0)

	if err := hydrateScanAuthSecret(database, &config); err != nil {
		_ = database.FailScanJob(job.ID, err.Error())
		cleanupScanSecret(database, job.Config.AuthSecretRef)
		setScanProgress(database, redisRuntime, job, core.ScanJobStatusFailed, workerID, err.Error(), 0)
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
			setScanProgress(database, redisRuntime, job, core.ScanJobStatusTimedOut, workerID, message, 0)
			return true, err
		}
		_ = database.FailScanJob(job.ID, err.Error())
		setScanProgress(database, redisRuntime, job, core.ScanJobStatusFailed, workerID, err.Error(), 0)
		return true, err
	}
	cancelled, err = scanJobCancelled(database, job.ID)
	if err != nil {
		return true, err
	}
	if cancelled {
		setScanProgress(database, redisRuntime, job, core.ScanJobStatusCancelled, workerID, "scan cancelled", 0)
		return true, nil
	}

	for _, res := range results {
		cancelled, err = scanJobCancelled(database, job.ID)
		if err != nil {
			return true, err
		}
		if cancelled {
			setScanProgress(database, redisRuntime, job, core.ScanJobStatusCancelled, workerID, "scan cancelled", 0)
			return true, nil
		}
		savedResult, err := database.SaveScanResult(core.ScanResult{
			TenantID:       job.TenantID,
			ProjectID:      job.ProjectID,
			JobID:          job.ID,
			SuiteID:        job.SuiteID,
			SchemaVersion:  res.SchemaVersion,
			InventoryID:    job.InventoryID,
			TestType:       res.TestType,
			Vulnerable:     res.Vulnerable,
			Severity:       res.Severity,
			Description:    res.Description,
			Proof:          res.Proof,
			ResponseStatus: res.ResponseStatus,
			ResponseHeader: res.ResponseHeader,
			ResponseBody:   res.ResponseBody,
			CreatedAt:      time.Now().UTC(),
		})
		if err != nil {
			_ = database.FailScanJob(job.ID, err.Error())
			setScanProgress(database, redisRuntime, job, core.ScanJobStatusFailed, workerID, err.Error(), len(results))
			return true, err
		}
		if savedResult != nil && savedResult.Vulnerable {
			if _, err := database.UpsertIssueFromScanResult(*savedResult); err != nil {
				_ = database.FailScanJob(job.ID, err.Error())
				setScanProgress(database, redisRuntime, job, core.ScanJobStatusFailed, workerID, err.Error(), len(results))
				return true, err
			}
		}
	}

	if err := database.CompleteScanJob(job.ID, len(results)); err != nil {
		setScanProgress(database, redisRuntime, job, core.ScanJobStatusFailed, workerID, err.Error(), len(results))
		return true, err
	}
	setScanProgress(database, redisRuntime, job, core.ScanJobStatusCompleted, workerID, "", len(results))
	log.Printf("Completed scan job id=%s results=%d", job.ID.Hex(), len(results))
	return true, nil
}

func processQueuedScanJob(ctx context.Context, consumer queue.Consumer, database *db.DB, engine scanner.Executor, workerID string, redisRuntime *coordination.RedisRuntime, scanLimits scancontrol.Config) (bool, error) {
	message, err := consumer.Consume(ctx)
	if err != nil {
		if errors.Is(err, queue.ErrNoMessage) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return false, nil
		}
		return false, err
	}
	envelope, err := queue.DecodeEnvelope(message)
	if err != nil {
		log.Printf("Dropping malformed scan job queue message key=%s: %v", message.Key, err)
		return true, consumer.Commit(context.Background(), message)
	}
	if envelope.PayloadType != queue.PayloadScanJobQueuedV1 {
		log.Printf("Dropping unexpected scan job payload type key=%s payload_type=%s", message.Key, envelope.PayloadType)
		return true, consumer.Commit(context.Background(), message)
	}
	var event queue.ScanJobEvent
	if err := json.Unmarshal(envelope.Payload, &event); err != nil {
		log.Printf("Dropping malformed scan job event key=%s: %v", message.Key, err)
		return true, consumer.Commit(context.Background(), message)
	}
	jobID, err := primitive.ObjectIDFromHex(event.JobID)
	if err != nil {
		log.Printf("Dropping scan job event with invalid job id key=%s job_id=%s", message.Key, event.JobID)
		return true, consumer.Commit(context.Background(), message)
	}
	job, err := database.ClaimScanJobByID(jobID, workerID)
	if err != nil {
		return false, err
	}
	if job == nil {
		return true, consumer.Commit(context.Background(), message)
	}
	processed, processErr := processClaimedJob(database, engine, workerID, redisRuntime, scanLimits, job)
	commitErr := consumer.Commit(context.Background(), message)
	if processErr != nil {
		return processed, processErr
	}
	return processed, commitErr
}

func newScannerQueueConsumer() (queue.Consumer, error) {
	if !scannerQueueEnabled() {
		return nil, nil
	}
	cfg := queue.LoadKafkaConfigFromEnv([]string{queue.TopicScanJobs})
	cfg.Topics = []string{queue.TopicScanJobs}
	if group := strings.TrimSpace(os.Getenv("KARAXYS_SCANNER_WORKER_CONSUMER_GROUP")); group != "" {
		cfg.ConsumerGroup = group
	} else {
		cfg.ConsumerGroup = "karaxys-scanner-worker"
	}
	cfg.ClientID = strings.TrimSpace(cfg.ClientID)
	if cfg.ClientID == "" {
		cfg.ClientID = "karaxys-backend"
	}
	cfg.ClientID += "-scanner-worker"
	return queue.NewKafkaConsumer(cfg)
}

func scannerQueueEnabled() bool {
	if config.IsProduction() {
		return true
	}
	raw := strings.TrimSpace(os.Getenv("KARAXYS_QUEUE_ENABLED"))
	if raw == "" {
		return false
	}
	enabled, err := strconv.ParseBool(raw)
	if err != nil {
		log.Printf("Invalid KARAXYS_QUEUE_ENABLED value %q; scanner queue disabled", raw)
		return false
	}
	return enabled
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

func setScanProgress(database *db.DB, redisRuntime *coordination.RedisRuntime, job *core.ScanJob, status string, workerID string, message string, resultsCount int) {
	if job == nil {
		return
	}
	if database != nil {
		if err := database.SaveScanProgressEvent(core.ScanProgressEvent{
			TenantID:     job.TenantID,
			ProjectID:    job.ProjectID,
			JobID:        job.ID,
			InventoryID:  job.InventoryID,
			Status:       status,
			WorkerID:     workerID,
			Message:      message,
			ResultsCount: resultsCount,
			CreatedAt:    time.Now().UTC(),
		}); err != nil {
			log.Printf("Failed to save scan progress event job=%s status=%s: %v", job.ID.Hex(), status, err)
		}
	}
	if redisRuntime == nil || redisRuntime.Progress == nil {
		return
	}
	if err := redisRuntime.Progress.Set(context.Background(), coordination.ScanProgress{
		JobID:        job.ID.Hex(),
		Status:       status,
		WorkerID:     workerID,
		Message:      message,
		ResultsCount: resultsCount,
		UpdatedAt:    time.Now().UTC(),
	}, redisRuntime.ProgressTTL); err != nil {
		log.Printf("Failed to update scan progress job=%s status=%s: %v", job.ID.Hex(), status, err)
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
