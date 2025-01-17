package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	vt "github.com/VirusTotal/vt-go"
)

func getFiles(path string) ([]string, error) {
	var files []string

	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !fileInfo.IsDir() {
		return []string{path}, nil
	}

	err = filepath.Walk(path, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})

	return files, err
}

func scanFile(client *vt.Client, filepath string, statusMgr *StatusManager, results chan<- string) {
	ctx := context.Background()

	statusMgr.UpdateStatus(filepath, "pending")

	// Open file
	file, err := os.Open(filepath)
	if err != nil {
		statusMgr.UpdateStatus(filepath, fmt.Sprintf("error: %v", err))
		results <- filepath
		return
	}
	defer file.Close()

	// Get upload URL for large files
	statusMgr.UpdateStatus(filepath, "uploading")

	uploadURL, err := client.GetUploadURL(ctx)
	if err != nil {
		statusMgr.UpdateStatus(filepath, fmt.Sprintf("error: %v", err))
		results <- filepath
		return
	}

	// Upload file
	analysis, err := client.ScanFileWithURL(ctx, file, uploadURL)
	if err != nil {
		statusMgr.UpdateStatus(filepath, fmt.Sprintf("error: %v", err))
		results <- filepath
		return
	}

	// Add comment
	comment := fmt.Sprintf("Uploaded from path: %s", filepath)
	_, err = client.AddComment(ctx, analysis.ID, comment)
	if err != nil {
		// Log error but continue
		fmt.Printf("Error adding comment for %s: %v\n", filepath, err)
	}

	statusMgr.UpdateStatus(filepath, "waiting for results")

	// Monitor analysis
	for {
		analysis, err := client.GetAnalysis(ctx, analysis.ID)
		if err != nil {
			statusMgr.UpdateStatus(filepath, fmt.Sprintf("error: %v", err))
			results <- filepath
			return
		}

		if analysis.Status == "completed" {
			// Get detailed file report
			file, err := client.GetObject(ctx, vt.URL("files/"+analysis.SHA256))
			if err != nil {
				statusMgr.UpdateStatus(filepath, fmt.Sprintf("error: %v", err))
				results <- filepath
				return
			}

			var issues []Issue
			lastAnalysis, err := file.Get("last_analysis_results")
			if err != nil {
				statusMgr.UpdateStatus(filepath, fmt.Sprintf("error: %v", err))
				results <- filepath
				return
			}

			// Parse analysis results
			results := lastAnalysis.(map[string]interface{})
			for engine, data := range results {
				details := data.(map[string]interface{})
				category := details["category"].(string)
				if category != "undetected" {
					issues = append(issues, Issue{
						Engine:   engine,
						Category: category,
						Result:   fmt.Sprint(details["result"]),
					})
				}
			}

			// Update final status
			if len(issues) == 0 {
				statusMgr.UpdateStatus(filepath, "clean")
			} else {
				status := "issues reported\n"
				for _, issue := range issues {
					status += fmt.Sprintf("- %s: %s\n", issue.Engine, issue.Result)
				}
				statusMgr.UpdateStatus(filepath, status)
			}

			results <- filepath
			return
		}

		statusMgr.UpdateStatus(filepath, "processing")
		time.Sleep(time.Second * 30) // Poll every 30 seconds
	}
}