package main

import (
	"testing"
)

func TestGetFiles(t *testing.T) {
	// Test single file
	files, err := getFiles("main.go")
	if err != nil {
		t.Errorf("Error getting single file: %v", err)
	}
	if len(files) != 1 {
		t.Errorf("Expected 1 file, got %d", len(files))
	}

	// Test directory
	files, err = getFiles(".")
	if err != nil {
		t.Errorf("Error getting directory files: %v", err)
	}
	if len(files) == 0 {
		t.Error("Expected multiple files, got 0")
	}
}