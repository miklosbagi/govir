package main

import (
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"govir/internal/vtclient"
)

func getFileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("error calculating hash: %v", err)
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

type fileStatus struct {
	displayPath string
	status      string
	result      string
	detections  map[string]vtclient.Detection
	err         error
}

type statusManager struct {
	mu           sync.Mutex
	statuses     map[string]*fileStatus
	debug        bool
	printedLines int // Track number of lines printed
}

func newStatusManager(debug bool) *statusManager {
	return &statusManager{
		statuses: make(map[string]*fileStatus),
		debug:    debug,
	}
}

func (sm *statusManager) updateStatus(displayPath, status string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, exists := sm.statuses[displayPath]; !exists {
		sm.statuses[displayPath] = &fileStatus{displayPath: displayPath}
	}
	sm.statuses[displayPath].status = status
	sm.printStatuses()
}

func (sm *statusManager) setResult(displayPath, result string, detections map[string]vtclient.Detection) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, exists := sm.statuses[displayPath]; !exists {
		sm.statuses[displayPath] = &fileStatus{displayPath: displayPath}
	}
	sm.statuses[displayPath].result = result
	sm.statuses[displayPath].detections = detections
	sm.printStatuses()
}

func (sm *statusManager) setError(displayPath string, err error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, exists := sm.statuses[displayPath]; !exists {
		sm.statuses[displayPath] = &fileStatus{displayPath: displayPath}
	}
	sm.statuses[displayPath].err = err
	sm.printStatuses()
}

func (sm *statusManager) printStatuses() {
	if sm.debug {
		return // Don't update status lines in debug mode
	}

	// Move cursor up by number of lines we printed last time
	if sm.printedLines > 0 {
		fmt.Printf("\033[%dA\r", sm.printedLines) // Move cursor up and to start of line
	}

	// Print current status of each file
	sm.printedLines = 0 // Reset counter for new output
	for _, status := range sm.statuses {
		// Clear the current line and print the new status
		fmt.Printf("\033[K") // Clear line
		if status.err != nil {
			fmt.Printf("%s: error - %v", status.displayPath, status.err)
			sm.printedLines++
		} else if status.result != "" {
			fmt.Printf("%s", status.result)
			sm.printedLines++
			if status.detections != nil {
				for engine, detection := range status.detections {
					fmt.Printf("\n\033[K- %s: %s", engine, detection.Result)
					sm.printedLines++
				}
			}
		} else {
			fmt.Printf("%s: %s", status.displayPath, status.status)
			sm.printedLines++
		}

		// Move to next line if there are more statuses to print
		if sm.printedLines > 0 && sm.printedLines < len(sm.statuses) {
			fmt.Print("\n")
		}
	}

	// Print newline only after all statuses if we printed anything
	if sm.printedLines > 0 {
		fmt.Print("\n")
	}
}

// getVersionInfo attempts to read version information from a 'ver' file in the same directory
func getVersionInfo(filePath string) (string, error) {
	dir := filepath.Dir(filePath)
	verFile := filepath.Join(dir, "ver")

	content, err := os.ReadFile(verFile)
	if err != nil {
		return "", err
	}

	// Trim any whitespace or newlines
	return strings.TrimSpace(string(content)), nil
}

func processFile(ctx context.Context, client *vtclient.Client, displayPath string, sm *statusManager, rateLimiter <-chan time.Time) {
	// Get absolute path
	absPath, err := filepath.Abs(displayPath)
	if err != nil {
		sm.setError(displayPath, fmt.Errorf("error getting absolute path: %v", err))
		return
	}

	// Check if file exists
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		sm.setError(displayPath, fmt.Errorf("file not found"))
		return
	}

	sm.updateStatus(displayPath, "calculating hash")
	hash, err := getFileHash(absPath)
	if err != nil {
		sm.setError(displayPath, fmt.Errorf("error getting hash: %v", err))
		return
	}

	sm.updateStatus(displayPath, "checking existing analysis")
	fileInfo, err := client.GetAnalysis(ctx, hash)
	if err != nil && !strings.Contains(err.Error(), "not found") {
		sm.setError(displayPath, fmt.Errorf("error checking file: %v", err))
		return
	}

	if fileInfo != nil && fileInfo.Status == "completed" {
		vtURL := fmt.Sprintf("%s/%s", vtclient.GuiBaseURL, hash)
		if fileInfo.LastAnalysisStats.Malicious == 0 && fileInfo.LastAnalysisStats.Suspicious == 0 {
			sm.setResult(displayPath, fmt.Sprintf("%s: [clean](%s)", displayPath, vtURL), nil)
		} else {
			sm.setResult(displayPath, fmt.Sprintf("%s: [issues reported](%s)", displayPath, vtURL), fileInfo.Detections)
		}
		return
	}

	// Wait for rate limiter before upload
	<-rateLimiter

	sm.updateStatus(displayPath, "uploading file")
	uploadURL, err := client.GetUploadURL(ctx)
	if err != nil {
		sm.setError(displayPath, fmt.Errorf("error getting upload URL: %v", err))
		return
	}

	analysis, err := client.UploadFile(ctx, uploadURL, absPath)
	if err != nil {
		sm.setError(displayPath, fmt.Errorf("error uploading file: %v", err))
		return
	}

	// Add comment with version info if available, otherwise use file path
	var comment string
	if verInfo, err := getVersionInfo(absPath); err == nil && verInfo != "" {
		comment = fmt.Sprintf("Package: %s", verInfo)
	} else {
		comment = fmt.Sprintf("File path: %s", displayPath)
	}

	existingComments, err := client.GetComments(ctx, hash)
	if err == nil {
		commentExists := false
		for _, existing := range existingComments {
			if existing == comment {
				commentExists = true
				break
			}
		}
		if !commentExists {
			_ = client.AddComment(ctx, hash, comment)
		}
	}

	// Poll for results
	pollStart := time.Now()
	maxWaitTime := 5 * time.Minute
	vtURL := fmt.Sprintf("%s/%s", vtclient.GuiBaseURL, hash)

	for {
		if time.Since(pollStart) > maxWaitTime {
			sm.setError(displayPath, fmt.Errorf("analysis timeout after %v", maxWaitTime))
			return
		}

		analysis, err = client.GetAnalysis(ctx, hash)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				sm.updateStatus(displayPath, "waiting for analysis to begin")
				time.Sleep(10 * time.Second)
				continue
			}
			sm.setError(displayPath, fmt.Errorf("error getting analysis: %v", err))
			return
		}

		total := analysis.LastAnalysisStats.Harmless +
			analysis.LastAnalysisStats.Malicious +
			analysis.LastAnalysisStats.Suspicious +
			analysis.LastAnalysisStats.Undetected

		if analysis.LastAnalysisStats.InProgress == 0 && total > 0 {
			if analysis.LastAnalysisStats.Malicious == 0 && analysis.LastAnalysisStats.Suspicious == 0 {
				sm.setResult(displayPath, fmt.Sprintf("%s: [clean](%s)", displayPath, vtURL), nil)
			} else {
				sm.setResult(displayPath, fmt.Sprintf("%s: [issues reported](%s)", displayPath, vtURL), analysis.Detections)
			}
			return
		}

		sm.updateStatus(displayPath, fmt.Sprintf("analysis in progress (%d/%d scanners reported)",
			total, total+analysis.LastAnalysisStats.InProgress))
		time.Sleep(10 * time.Second)
	}
}

func main() {
	// Parse command line flags
	debug := flag.Bool("debug", false, "Enable debug logging")
	flag.Parse()

	// Get debug setting from environment variable if not set via flag
	if !*debug {
		debugEnv := os.Getenv("GOVIR_DEBUG")
		*debug = debugEnv == "1" || debugEnv == "true"
	}

	// Check for API key
	apiKey := os.Getenv("VT_API_KEY")
	if apiKey == "" {
		log.Fatal("VT_API_KEY environment variable is required")
	}

	// Get files to scan from command line arguments
	files := flag.Args()
	if len(files) == 0 {
		log.Fatal("No files specified")
	}

	// Create context
	ctx := context.Background()

	// Create VirusTotal client with debug mode
	client := vtclient.New(apiKey).WithDebug(*debug)

	// Create status manager
	sm := newStatusManager(*debug)

	// Create rate limiter - 3 seconds between API requests
	rateLimiter := time.NewTicker(3 * time.Second)
	defer rateLimiter.Stop()

	// Create wait group for parallel processing
	var wg sync.WaitGroup

	// Process files in parallel
	for _, file := range files {
		wg.Add(1)
		go func(file string) {
			defer wg.Done()
			processFile(ctx, client, file, sm, rateLimiter.C)
		}(file)
	}

	// Wait for all files to complete
	wg.Wait()
}
