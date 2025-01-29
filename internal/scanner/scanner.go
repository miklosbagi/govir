package scanner

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"sync"
	"time"

	"govir/internal/vtclient"
)

// VTClient defines the interface for VirusTotal API operations
type VTClient interface {
	GetUploadURL(ctx context.Context) (string, error)
	UploadFile(ctx context.Context, uploadURL, filepath string) (string, error)
	GetAnalysis(ctx context.Context, id string) (*vtclient.FileReport, error)
	AddComment(ctx context.Context, id, comment string) error
}

type Scanner struct {
	client VTClient
	status map[string]*FileStatus
	mu     sync.RWMutex
}

type FileStatus struct {
	Path       string
	Status     string
	Progress   *ScanProgress
	Issues     []Issue
	AnalysisID string
	StartTime  time.Time
	mu         sync.Mutex
}

type ScanProgress struct {
	TotalEngines     int
	CompletedEngines int
	Phase            string
	TimeElapsed      time.Duration
}

type Issue struct {
	Engine   string
	Category string
	Result   string
}

func New(client VTClient) *Scanner {
	return &Scanner{
		client: client,
		status: make(map[string]*FileStatus),
	}
}

func (s *Scanner) ScanFile(ctx context.Context, path string) error {
	s.updateStatus(path, "pending", nil)
	startTime := time.Now()

	// Get upload URL
	uploadURL, err := s.client.GetUploadURL(ctx)
	if err != nil {
		s.updateStatus(path, fmt.Sprintf("error: %v", err), nil)
		return fmt.Errorf("getting upload URL: %w", err)
	}

	s.updateStatus(path, "uploading", &ScanProgress{Phase: "upload"})

	// Upload file
	analysisID, err := s.client.UploadFile(ctx, uploadURL, path)
	if err != nil {
		s.updateStatus(path, fmt.Sprintf("error: %v", err), nil)
		return fmt.Errorf("uploading file: %w", err)
	}

	s.updateStatus(path, "waiting for results", &ScanProgress{Phase: "analysis"})

	// Poll for results
	var fileHash string
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(15 * time.Second): // Rate limiting
			report, err := s.client.GetAnalysis(ctx, analysisID)
			if err != nil {
				s.updateStatus(path, fmt.Sprintf("error: %v", err), nil)
				return fmt.Errorf("getting analysis: %w", err)
			}

			// Store the file hash for commenting later
			if fileHash == "" && report.Meta.FileInfo.SHA256 != "" {
				fileHash = report.Meta.FileInfo.SHA256
			}

			// Calculate progress
			progress := &ScanProgress{
				TotalEngines: report.Data.Attributes.Stats.Malicious +
					report.Data.Attributes.Stats.Suspicious +
					report.Data.Attributes.Stats.Undetected +
					report.Data.Attributes.Stats.Harmless +
					report.Data.Attributes.Stats.Timeout +
					report.Data.Attributes.Stats.ConfirmedTimeout +
					report.Data.Attributes.Stats.Failure +
					report.Data.Attributes.Stats.TypeUnsupported,
				CompletedEngines: len(report.Data.Attributes.Results),
				Phase:            report.Data.Attributes.Status,
				TimeElapsed:      time.Since(startTime),
			}

			if report.Data.Attributes.Status == "completed" {
				s.processResults(path, report)

				// Add comment after analysis is complete
				if fileHash != "" {
					comment := fmt.Sprintf("File path: %s (Scan time: %s)",
						path,
						startTime.Format(time.RFC3339))
					if err := s.client.AddComment(ctx, fileHash, comment); err != nil {
						if vtErr, ok := err.(*vtclient.VTError); ok && vtErr != nil {
							if !vtErr.IsAlreadyExists() {
								log.Printf("Warning: failed to add comment for %s: %v", path, err)
							}
						} else {
							log.Printf("Warning: failed to add comment for %s: %v", path, err)
						}
					}
				}

				return nil
			} else if report.Data.Attributes.Status == "failed" {
				s.updateStatus(path, "error: analysis failed", progress)
				return fmt.Errorf("analysis failed")
			}

			s.updateStatus(path, fmt.Sprintf("processing (%s - %d/%d engines, %s elapsed)",
				report.Data.Attributes.Status,
				progress.CompletedEngines,
				progress.TotalEngines,
				progress.TimeElapsed.Round(time.Second)),
				progress)
		}
	}
}

func (s *Scanner) updateStatus(path, status string, progress *ScanProgress) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if fileStatus, exists := s.status[path]; exists {
		fileStatus.mu.Lock()
		fileStatus.Status = status
		if progress != nil {
			fileStatus.Progress = progress
		}
		fileStatus.mu.Unlock()
	} else {
		s.status[path] = &FileStatus{
			Path:      path,
			Status:    status,
			Progress:  progress,
			StartTime: time.Now(),
		}
	}

	// Print current status with progress if available
	if progress != nil && progress.TotalEngines > 0 {
		fmt.Printf("%s (%s): %s (%d/%d engines)\n",
			filepath.Base(path),
			path,
			status,
			progress.CompletedEngines,
			progress.TotalEngines)
	} else {
		fmt.Printf("%s (%s): %s\n",
			filepath.Base(path),
			path,
			status)
	}
}

func (s *Scanner) processResults(path string, report *vtclient.FileReport) {
	s.mu.Lock()
	defer s.mu.Unlock()

	fileStatus := s.status[path]
	if fileStatus == nil {
		fileStatus = &FileStatus{Path: path}
		s.status[path] = fileStatus
	}

	fileStatus.mu.Lock()
	defer fileStatus.mu.Unlock()

	var issues []Issue
	for engineName, result := range report.Data.Attributes.Results {
		// Skip results that are not actual detections
		if result.Category == "undetected" ||
			result.Category == "harmless" ||
			result.Category == "type-unsupported" ||
			result.Category == "timeout" ||
			result.Category == "confirmed-timeout" ||
			result.Category == "failure" ||
			result.Result == "" {
			continue
		}

		issues = append(issues, Issue{
			Engine:   engineName,
			Category: result.Category,
			Result:   result.Result,
		})
	}

	if len(issues) == 0 {
		fileStatus.Status = "clean"
		fmt.Printf("%s (%s): clean\n",
			filepath.Base(path),
			path)
	} else {
		fileStatus.Status = "issues reported"
		fileStatus.Issues = issues
		fmt.Printf("%s (%s): issues reported\n",
			filepath.Base(path),
			path)
		for _, issue := range issues {
			fmt.Printf("- %s: %s\n", issue.Engine, issue.Result)
		}
	}
}
