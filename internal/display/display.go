package display

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miklosbagi/govir/internal/scanner"
)

// Display handles the CLI user interface
type Display struct {
	scanner    *scanner.Scanner
	files      []string
	updateLock sync.Mutex
	done       bool
}

// NewDisplay creates a new display instance
func NewDisplay(scanner *scanner.Scanner, files []string) *Display {
	return &Display{
		scanner: scanner,
		files:   files,
	}
}

// Start begins the display update loop
func (d *Display) Start() {
	d.updateLock.Lock()
	defer d.updateLock.Unlock()

	d.updateDisplay()

	// Update display every second
	go func() {
		for !d.done {
			time.Sleep(time.Second)
			d.updateLock.Lock()
			d.updateDisplay()
			d.updateLock.Unlock()
		}
	}()
}

// Stop stops the display update loop
func (d *Display) Stop() {
	d.done = true
}

// updateDisplay updates the CLI display with current status
func (d *Display) updateDisplay() {
	// Clear screen and move cursor to top
	fmt.Print("\033[H\033[2J")

	allDone := true
	for _, file := range d.files {
		status := d.scanner.GetStatus(file)
		if status == nil {
			fmt.Printf("%s: pending\n", file)
			allDone = false
			continue
		}

		switch status.Status {
		case "clean":
			fmt.Printf("%s: clean\n", file)
		case "issues":
			fmt.Printf("%s: issues reported\n", file)
			for _, issue := range status.Issues {
				fmt.Printf("- %s: %s\n", issue.Engine, issue.Result)
			}
		default:
			fmt.Printf("%s: %s\n", file, status.Status)
			allDone = false
		}
	}

	if allDone {
		d.done = true
	}
}