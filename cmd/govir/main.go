package main

import (
	"flag"
	"fmt"
	"os"
	"sync"

	"github.com/miklosbagi/govir/internal/config"
	"github.com/miklosbagi/govir/internal/display"
	"github.com/miklosbagi/govir/internal/scanner"
	"github.com/miklosbagi/govir/internal/virustotal"
)

func main() {
	configPath := flag.String("config", "", "Path to config file")
	flag.Parse()

	if len(flag.Args()) == 0 {
		fmt.Println("Error: no files or directories specified")
		fmt.Println("Usage: govir [-config path/to/config.yaml] file1 dir1 file2 ...")
		os.Exit(1)
	}

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Printf("Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Create VirusTotal client
	client := virustotal.NewClient(cfg.APIKey)

	// Create scanner
	s := scanner.NewScanner(client)

	// Collect files
	files, err := s.CollectFiles(flag.Args())
	if err != nil {
		fmt.Printf("Error collecting files: %v\n", err)
		os.Exit(1)
	}

	if len(files) == 0 {
		fmt.Println("No files found to scan")
		os.Exit(0)
	}

	// Create display
	d := display.NewDisplay(s, files)
	d.Start()
	defer d.Stop()

	// Start scanning files concurrently
	var wg sync.WaitGroup
	for _, file := range files {
		wg.Add(1)
		go func(file string) {
			defer wg.Done()
			if err := s.ScanFile(file); err != nil {
				fmt.Printf("Error scanning %s: %v\n", file, err)
			}
		}(file)
	}

	// Wait for all scans to complete
	wg.Wait()
}