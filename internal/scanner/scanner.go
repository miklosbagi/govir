package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/miklosbagi/govir/internal/virustotal"
)

// FileStatus represents the current status of a file being scanned
type FileStatus struct {
	Path    string
	Status  string // pending, uploading, waiting, processing, clean, issues
	Issues  []virustotal.Issue
	Comment string
}

// Scanner handles the scanning of files
type Scanner struct {
	client    *virustotal.Client
	statuses  map[string]*FileStatus
	statusMux sync.RWMutex
}

// NewScanner creates a new scanner instance
func NewScanner(client *virustotal.Client) *Scanner {
	return &Scanner{
		client:   client,
		statuses: make(map[string]*FileStatus),
	}
}

// CollectFiles recursively collects files from the provided paths
func (s *Scanner) CollectFiles(paths []string) ([]string, error) {
	var files []string
	seen := make(map[string]bool)

	for _, path := range paths {
		err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				absPath, err := filepath.Abs(path)
				if err != nil {
					return err
				}
				if !seen[absPath] {
					files = append(files, absPath)
					seen[absPath] = true
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return files, nil
}

// ScanFile scans a single file and updates its status
func (s *Scanner) ScanFile(filePath string) error {
	s.updateStatus(filePath, "pending", nil)

	// Get upload URL
	uploadURL, err := s.client.GetUploadURL()
	if err != nil {
		return fmt.Errorf("failed to get upload URL: %w", err)
	}

	s.updateStatus(filePath, "uploading", nil)

	// Upload file
	analysisID, err := s.client.UploadFile(filePath, uploadURL)
	if err != nil {
		return fmt.Errorf("failed to upload file: %w", err)
	}

	// Add comment with file path
	comment := fmt.Sprintf("File path: %s", filePath)
	if err := s.client.AddComment(analysisID, comment); err != nil {
		// Non-fatal error, continue with analysis
		fmt.Printf("Warning: failed to add comment for %s: %v\n", filePath, err)
	}

	s.updateStatus(filePath, "waiting", nil)

	// Monitor analysis status
	for {
		status, err := s.client.GetAnalysisStatus(analysisID)
		if err != nil {
			return fmt.Errorf("failed to get analysis status: %w", err)
		}

		switch status.Status {
		case "completed":
			if len(status.Issues) > 0 {
				s.updateStatus(filePath, "issues", status.Issues)
			} else {
				s.updateStatus(filePath, "clean", nil)
			}
			return nil
		case "queued", "in-progress":
			s.updateStatus(filePath, "processing", nil)
		default:
			return fmt.Errorf("unexpected analysis status: %s", status.Status)
		}

		time.Sleep(10 * time.Second) // Be nice to the API
	}
}

// GetStatus returns the current status of a file
func (s *Scanner) GetStatus(filePath string) *FileStatus {
	s.statusMux.RLock()
	defer s.statusMux.RUnlock()
	return s.statuses[filePath]
}

// updateStatus updates the status of a file
func (s *Scanner) updateStatus(filePath, status string, issues []virustotal.Issue) {
	s.statusMux.Lock()
	defer s.statusMux.Unlock()

	if _, exists := s.statuses[filePath]; !exists {
		s.statuses[filePath] = &FileStatus{Path: filePath}
	}

	s.statuses[filePath].Status = status
	if issues != nil {
		s.statuses[filePath].Issues = issues
	}
}