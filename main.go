package main

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"gopkg.in/yaml.v3"
)

type Config struct {
	S3 struct {
		Endpoint        string `yaml:"endpoint"`
		Region          string `yaml:"region"`
		Bucket          string `yaml:"bucket"`
		AccessKeyID     string `yaml:"access_key_id"`
		SecretAccessKey string `yaml:"secret_access_key"`
		ForcePathStyle  bool   `yaml:"force_path_style"`
	} `yaml:"s3"`
	Download struct {
		Directory         string `yaml:"directory"`
		Workers           int    `yaml:"workers"`
		Retries           int    `yaml:"retries"`
		RetryDelaySeconds int    `yaml:"retry_delay_seconds"`
		StateFile         string `yaml:"state_file"`
		LogFile           string `yaml:"log_file"`
	} `yaml:"download"`
}

type ObjectState struct {
	ETag         string    `json:"etag"`
	Size         int64     `json:"size"`
	LastModified time.Time `json:"last_modified,omitempty"`
	SHA256       string    `json:"sha256"`
	CompletedAt  time.Time `json:"completed_at"`
}

type State struct {
	Version int                    `json:"version"`
	Bucket  string                 `json:"bucket"`
	Objects map[string]ObjectState `json:"objects"`
}

type Job struct {
	Key          string
	ETag         string
	Size         int64
	LastModified time.Time
}

type Result struct {
	Job Job
	Err error
}

func main() {
	configPath := flag.String("config", "config.yaml", "path to YAML configuration")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("configuration: %v", err)
	}

	if cfg.Download.LogFile != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.Download.LogFile), 0755); err != nil && filepath.Dir(cfg.Download.LogFile) != "." {
			log.Fatalf("create log directory: %v", err)
		}
		f, err := os.OpenFile(cfg.Download.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("open log file: %v", err)
		}
		defer f.Close()
		log.SetOutput(io.MultiWriter(os.Stdout, f))
	}

	if err := run(cfg); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

func loadConfig(path string) (Config, error) {
	var cfg Config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	if cfg.S3.Endpoint == "" || cfg.S3.Bucket == "" || cfg.S3.AccessKeyID == "" || cfg.S3.SecretAccessKey == "" {
		return cfg, errors.New("s3.endpoint, s3.bucket, s3.access_key_id and s3.secret_access_key are required")
	}
	if cfg.S3.Region == "" {
		cfg.S3.Region = "us-east-1"
	}
	if cfg.Download.Directory == "" {
		cfg.Download.Directory = "./downloads"
	}
	if cfg.Download.Workers < 1 {
		cfg.Download.Workers = 4
	}
	if cfg.Download.Retries < 0 {
		cfg.Download.Retries = 0
	}
	if cfg.Download.RetryDelaySeconds < 1 {
		cfg.Download.RetryDelaySeconds = 2
	}
	if cfg.Download.StateFile == "" {
		cfg.Download.StateFile = "./s3downloader-state.json"
	}
	return cfg, nil
}

func run(cfg Config) error {
	ctx, stop := signalContext()
	defer stop()

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(cfg.S3.Region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			cfg.S3.AccessKeyID, cfg.S3.SecretAccessKey, "",
		)),
	)
	if err != nil {
		return fmt.Errorf("initialize AWS config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(cfg.S3.Endpoint)
		o.UsePathStyle = cfg.S3.ForcePathStyle
	})

	if err := os.MkdirAll(cfg.Download.Directory, 0755); err != nil {
		return fmt.Errorf("create download directory: %w", err)
	}

	state, err := loadState(cfg.Download.StateFile, cfg.S3.Bucket)
	if err != nil {
		return err
	}
	var stateMu sync.Mutex

	jobs := make(chan Job, cfg.Download.Workers*2)
	results := make(chan Result, cfg.Download.Workers*2)

	var downloaded atomic.Int64
	var skipped atomic.Int64
	var failed atomic.Int64
	var total atomic.Int64
	listErr := make(chan error, 1)

	var workers sync.WaitGroup
	for i := 0; i < cfg.Download.Workers; i++ {
		workers.Add(1)
		go func(workerID int) {
			defer workers.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					results <- Result{Job: job, Err: ctx.Err()}
					continue
				}

				localPath, pathErr := objectPath(cfg.Download.Directory, job.Key)
				if pathErr != nil {
					results <- Result{Job: job, Err: pathErr}
					continue
				}

				stateMu.Lock()
				previous, exists := state.Objects[job.Key]
				stateMu.Unlock()
				if exists && previous.ETag == job.ETag && previous.Size == job.Size &&
					fileHasSize(localPath, job.Size) {
					localSHA, hashErr := sha256File(localPath)
					if hashErr == nil && previous.SHA256 != "" && localSHA == previous.SHA256 {
						skipped.Add(1)
						results <- Result{Job: job}
						continue
					}
				}
				/* checkpoint mismatch or missing file: fetch again */

				err := downloadWithRetry(ctx, client, cfg, job, localPath)
				if err != nil {
					failed.Add(1)
					results <- Result{Job: job, Err: err}
					continue
				}

				sha, err := sha256File(localPath)
				if err != nil {
					failed.Add(1)
					results <- Result{Job: job, Err: fmt.Errorf("calculate final SHA256: %w", err)}
					continue
				}

				stateMu.Lock()
				state.Objects[job.Key] = ObjectState{
					ETag: job.ETag, Size: job.Size, LastModified: job.LastModified,
					SHA256: sha, CompletedAt: time.Now().UTC(),
				}
				saveErr := saveState(cfg.Download.StateFile, state)
				stateMu.Unlock()
				if saveErr != nil {
					failed.Add(1)
					results <- Result{Job: job, Err: fmt.Errorf("save checkpoint: %w", saveErr)}
					continue
				}
				downloaded.Add(1)
				results <- Result{Job: job}
			}
		}(i + 1)
	}

	// The producer lists objects page by page. Workers download concurrently.
	go func() {
		defer close(jobs)
		paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
			Bucket: aws.String(cfg.S3.Bucket),
		})
		for paginator.HasMorePages() {
			if ctx.Err() != nil {
				return
			}
			page, err := paginator.NextPage(ctx)
			if err != nil {
				listErr <- fmt.Errorf("list bucket: %w", err)
				return
			}
			for _, obj := range page.Contents {
				if obj.Key == nil {
					continue
				}
				job := Job{Key: *obj.Key, Size: aws.ToInt64(obj.Size)}
				if obj.ETag != nil {
					job.ETag = strings.Trim(*obj.ETag, `"`)
				}
				if obj.LastModified != nil {
					job.LastModified = *obj.LastModified
				}
				total.Add(1)
				select {
				case jobs <- job:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	go func() {
		workers.Wait()
		close(results)
	}()

	var errorsFound []string
	for result := range results {
		if result.Err != nil {
			if !errors.Is(result.Err, context.Canceled) {
				log.Printf("ERROR %s: %v", result.Job.Key, result.Err)
				errorsFound = append(errorsFound, result.Job.Key+": "+result.Err.Error())
			}
			continue
		}
		if downloaded.Load()+skipped.Load() > 0 && (downloaded.Load()+skipped.Load())%100 == 0 {
			log.Printf("progress: completed=%d downloaded=%d skipped=%d failed=%d",
				downloaded.Load()+skipped.Load(), downloaded.Load(), skipped.Load(), failed.Load())
		}
	}

	log.Printf("finished: listed=%d downloaded=%d skipped=%d failed=%d",
		total.Load(), downloaded.Load(), skipped.Load(), failed.Load())
	if ctx.Err() != nil {
		log.Printf("stopped: checkpoint saved; restart the application to resume")
	}
	select {
	case err := <-listErr:
		return err
	default:
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if len(errorsFound) > 0 {
		return fmt.Errorf("%d object(s) failed; see log for details", len(errorsFound))
	}
	return nil
}

func downloadWithRetry(ctx context.Context, client *s3.Client, cfg Config, job Job, finalPath string) error {
	var lastErr error
	for attempt := 0; attempt <= cfg.Download.Retries; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if attempt > 0 {
			delay := time.Duration(cfg.Download.RetryDelaySeconds) * time.Second * time.Duration(attempt)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		lastErr = downloadOnce(ctx, client, cfg.S3.Bucket, job, finalPath)
		if lastErr == nil {
			return nil
		}
		log.Printf("WARN retry %d/%d for %s: %v", attempt+1, cfg.Download.Retries, job.Key, lastErr)
	}
	return lastErr
}

func downloadOnce(ctx context.Context, client *s3.Client, bucket string, job Job, finalPath string) error {
	input := &s3.GetObjectInput{
		Bucket:       aws.String(bucket),
		Key:          aws.String(job.Key),
		ChecksumMode: types.ChecksumModeEnabled,
	}
	out, err := client.GetObject(ctx, input)
	if err != nil {
		return fmt.Errorf("GetObject: %w", err)
	}
	defer out.Body.Close()

	if err := os.MkdirAll(filepath.Dir(finalPath), 0755); err != nil {
		return fmt.Errorf("create object directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(finalPath), ".s3download-*.part")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	h256, h1, hmd5 := sha256.New(), sha1.New(), md5.New()
	crc32h := crc32.NewIEEE()
	crc32ch := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	writer := io.MultiWriter(tmp, h256, h1, hmd5, crc32h, crc32ch)
	written, copyErr := io.Copy(writer, out.Body)
	if copyErr != nil {
		tmp.Close()
		return fmt.Errorf("write object: %w", copyErr)
	}
	if written != job.Size {
		tmp.Close()
		return fmt.Errorf("size mismatch: expected %d bytes, got %d", job.Size, written)
	}

	// Prefer an S3-provided checksum. ETag is used as MD5 only for a
	// simple (non-multipart-looking) ETag; multipart ETags are not MD5.
	if err := verifyChecksum(out, h256, h1, hmd5, crc32h, crc32ch); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := os.Rename(tmpName, finalPath); err != nil {
		return fmt.Errorf("commit downloaded file: %w", err)
	}
	return nil
}

func verifyChecksum(out *s3.GetObjectOutput, h256, h1, hmd5 io.Writer, crc32h, crc32ch io.Writer) error {
	// Hash implementations are passed as io.Writer to keep this helper small;
	// obtain sums through the concrete hash.Hash interfaces below.
	sum256 := h256.(interface{ Sum([]byte) []byte }).Sum(nil)
	sum1 := h1.(interface{ Sum([]byte) []byte }).Sum(nil)
	sumMD5 := hmd5.(interface{ Sum([]byte) []byte }).Sum(nil)
	sumCRC32 := crc32h.(interface{ Sum([]byte) []byte }).Sum(nil)
	sumCRC32C := crc32ch.(interface{ Sum([]byte) []byte }).Sum(nil)

	checks := []struct{ name, remote, local string }{
		{"SHA256", aws.ToString(out.ChecksumSHA256), base64.StdEncoding.EncodeToString(sum256)},
		{"SHA1", aws.ToString(out.ChecksumSHA1), base64.StdEncoding.EncodeToString(sum1)},
		{"CRC32", aws.ToString(out.ChecksumCRC32), base64.StdEncoding.EncodeToString(sumCRC32)},
		{"CRC32C", aws.ToString(out.ChecksumCRC32C), base64.StdEncoding.EncodeToString(sumCRC32C)},
	}
	for _, c := range checks {
		if c.remote != "" {
			if c.remote != c.local {
				return fmt.Errorf("%s checksum mismatch: S3=%s local=%s", c.name, c.remote, c.local)
			}
			return nil
		}
	}
	etag := strings.Trim(aws.ToString(out.ETag), `"`)
	if etag != "" && !strings.Contains(etag, "-") {
		if !strings.EqualFold(etag, hex.EncodeToString(sumMD5)) {
			return fmt.Errorf("ETag/MD5 mismatch: S3=%s local=%s", etag, hex.EncodeToString(sumMD5))
		}
	}
	// Some S3-compatible servers do not expose checksums. In that case a
	// local SHA256 is still calculated and persisted in the state file.
	return nil
}

func objectPath(root, key string) (string, error) {
	cleanKey := filepath.Clean(filepath.FromSlash(key))
	if cleanKey == "." || filepath.IsAbs(cleanKey) || cleanKey == ".." || strings.HasPrefix(cleanKey, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("unsafe object key path: %q", key)
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	target := filepath.Join(rootAbs, cleanKey)
	rel, err := filepath.Rel(rootAbs, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("object key escapes destination: %q", key)
	}
	return target, nil
}

func fileHasSize(path string, size int64) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Size() == size
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func loadState(path, bucket string) (*State, error) {
	state := &State{Version: 1, Bucket: bucket, Objects: make(map[string]ObjectState)}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state file: %w", err)
	}
	if err := json.Unmarshal(data, state); err != nil {
		return nil, fmt.Errorf("parse state file: %w", err)
	}
	if state.Bucket != bucket {
		return nil, fmt.Errorf("state file belongs to bucket %q, configured bucket is %q", state.Bucket, bucket)
	}
	if state.Objects == nil {
		state.Objects = make(map[string]ObjectState)
	}
	return state, nil
}

func saveState(path string, state *State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
