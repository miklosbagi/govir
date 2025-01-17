package config

import (
	"errors"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config holds the application configuration
type Config struct {
	APIKey string `yaml:"api_key"`
}

// LoadConfig loads configuration from environment variables, config file, and CLI flags
func LoadConfig(configPath string) (*Config, error) {
	config := &Config{}

	// First try environment variable
	if apiKey := os.Getenv("VT_API_KEY"); apiKey != "" {
		config.APIKey = apiKey
		return config, nil
	}

	// Then try config file if provided
	if configPath != "" {
		data, err := os.ReadFile(configPath)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		if err == nil {
			if err := yaml.Unmarshal(data, config); err != nil {
				return nil, err
			}
			if config.APIKey != "" {
				return config, nil
			}
		}
	}

	// Try default config locations
	homeDir, err := os.UserHomeDir()
	if err == nil {
		defaultPaths := []string{
			filepath.Join(homeDir, ".govir.yaml"),
			filepath.Join(homeDir, ".govir/config.yaml"),
			"config.yaml",
		}

		for _, path := range defaultPaths {
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			if err := yaml.Unmarshal(data, config); err != nil {
				continue
			}
			if config.APIKey != "" {
				return config, nil
			}
		}
	}

	return nil, errors.New("no API key found in environment variables or config files")
}