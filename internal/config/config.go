package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

type Config struct {
	APIKey string
}

func Load() (*Config, error) {
	// Try environment variable first
	apiKey := os.Getenv("VT_API_KEY")
	if apiKey != "" {
		return &Config{APIKey: apiKey}, nil
	}

	// Try config file
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err == nil {
		apiKey = viper.GetString("apikey")
		if apiKey != "" {
			return &Config{APIKey: apiKey}, nil
		}
	}

	return nil, fmt.Errorf("no VirusTotal API key found in environment variable VT_API_KEY or config.yaml")
}