package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"govir/internal/scanner"
	"govir/internal/vtclient"
)

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

	// Create VirusTotal client with debug mode
	client := vtclient.New(apiKey).WithDebug(*debug)

	// Create scanner
	s := scanner.New(client)

	// Get files to scan from command line arguments
	files := flag.Args()
	if len(files) == 0 {
		log.Fatal("No files specified")
	}

	// Create a WaitGroup to track all scans
	var wg sync.WaitGroup
	wg.Add(len(files))

	// Process each file
	for _, file := range files {
		go func(path string) {
			defer wg.Done()

			// Get absolute path
			absPath, err := filepath.Abs(path)
			if err != nil {
				log.Printf("Error getting absolute path for %s: %v", path, err)
				return
			}

			// Check if file exists
			if _, err := os.Stat(absPath); os.IsNotExist(err) {
				log.Printf("File not found: %s", absPath)
				return
			}

			// Scan file
			if err := s.ScanFile(context.Background(), absPath); err != nil {
				log.Printf("Error scanning %s: %v", absPath, err)
			}
		}(file)
	}

	// Wait for all scans to complete
	wg.Wait()
}

// collectFiles recursively collects all files from a path
func collectFiles(path string) ([]string, error) {
	var files []string

	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("error accessing path %s: %v", path, err)
	}

	if !fileInfo.IsDir() {
		return []string{path}, nil
	}

	err = filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
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
