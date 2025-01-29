package config

import (
	"os"
	"testing"
)

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		envVar  string
		wantErr bool
	}{
		{
			name:    "valid API key from env",
			envVar:  "test-api-key",
			wantErr: false,
		},
		{
			name:    "missing API key",
			envVar:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up environment
			if tt.envVar != "" {
				os.Setenv("VT_API_KEY", tt.envVar)
				defer os.Unsetenv("VT_API_KEY")
			} else {
				os.Unsetenv("VT_API_KEY")
			}

			cfg, err := Load()
			if (err != nil) != tt.wantErr {
				t.Errorf("Load() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && cfg.APIKey != tt.envVar {
				t.Errorf("Load() APIKey = %v, want %v", cfg.APIKey, tt.envVar)
			}
		})
	}
}