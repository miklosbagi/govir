package vtclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestClient_GetUploadURL(t *testing.T) {
	tests := []struct {
		name       string
		apiKey     string
		response   string
		statusCode int
		wantURL    string
		wantErr    bool
	}{
		{
			name:       "successful response",
			apiKey:     "test-key",
			response:   `{"data": "https://upload.virustotal.com/test"}`,
			statusCode: http.StatusOK,
			wantURL:    "https://upload.virustotal.com/test",
			wantErr:    false,
		},
		{
			name:       "unauthorized",
			apiKey:     "invalid-key",
			response:   `{"error": {"code": "WrongCredentialsError", "message": "Invalid API key"}}`,
			statusCode: http.StatusUnauthorized,
			wantURL:    "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("x-apikey") != tt.apiKey {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte(`{"error": {"code": "WrongCredentialsError", "message": "Invalid API key"}}`))
					return
				}

				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			client := New(tt.apiKey).WithBaseURL(server.URL)

			url, err := client.GetUploadURL(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("GetUploadURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if url != tt.wantURL {
				t.Errorf("GetUploadURL() = %v, want %v", url, tt.wantURL)
			}
		})
	}
}

func TestClient_GetAnalysis(t *testing.T) {
	tests := []struct {
		name       string
		apiKey     string
		hash       string
		response   string
		statusCode int
		wantStatus string
		wantStats  Stats
		wantErr    bool
	}{
		{
			name:   "successful response",
			apiKey: "test-key",
			hash:   "test-hash",
			response: `{
				"data": {
					"attributes": {
						"status": "completed",
						"stats": {
							"harmless": 0,
							"malicious": 1,
							"suspicious": 0
						}
					}
				}
			}`,
			statusCode: http.StatusOK,
			wantStatus: "completed",
			wantStats: Stats{
				Harmless:   0,
				Malicious:  1,
				Suspicious: 0,
			},
			wantErr: false,
		},
		{
			name:       "not found",
			apiKey:     "test-key",
			hash:       "nonexistent-hash",
			response:   `{"error": {"code": "NotFoundError", "message": "File not found"}}`,
			statusCode: http.StatusNotFound,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("x-apikey") != tt.apiKey {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte(`{"error": {"code": "WrongCredentialsError", "message": "Invalid API key"}}`))
					return
				}

				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			client := New(tt.apiKey).WithBaseURL(server.URL)

			analysis, err := client.GetAnalysis(context.Background(), tt.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAnalysis() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if analysis.Status != tt.wantStatus {
					t.Errorf("GetAnalysis() status = %v, want %v", analysis.Status, tt.wantStatus)
				}
				if analysis.Stats != tt.wantStats {
					t.Errorf("GetAnalysis() stats = %v, want %v", analysis.Stats, tt.wantStats)
				}
			}
		})
	}
}

func TestClient_UploadFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") != "test-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"data": {
				"id": "test-id"
			}
		}`))
	}))
	defer server.Close()

	client := New("test-key").WithBaseURL(server.URL)

	tmpfile, err := os.CreateTemp("", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte("test data")); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	analysis, err := client.UploadFile(context.Background(), server.URL+"/upload", tmpfile.Name())
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if analysis.Status != "queued" {
		t.Errorf("Expected status 'queued', got %s", analysis.Status)
	}
}
