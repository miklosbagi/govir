package vtclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_GetUploadURL(t *testing.T) {
	tests := []struct {
		name       string
		apiKey     string
		response   interface{}
		statusCode int
		wantURL    string
		wantErr    bool
	}{
		{
			name:   "successful response",
			apiKey: "test-key",
			response: UploadURLResponse{
				Data: struct {
					ID  string `json:"id"`
					URL string `json:"url"`
				}{
					URL: "https://upload.virustotal.com/test",
				},
			},
			statusCode: http.StatusOK,
			wantURL:    "https://upload.virustotal.com/test",
			wantErr:    false,
		},
		{
			name:       "unauthorized",
			apiKey:     "invalid-key",
			response:   map[string]string{"error": "unauthorized"},
			statusCode: http.StatusUnauthorized,
			wantURL:    "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Check request
				if r.Header.Get("x-apikey") != tt.apiKey {
					w.WriteHeader(http.StatusUnauthorized)
					json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
					return
				}

				// Send response
				w.WriteHeader(tt.statusCode)
				json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			// Create client with test server URL
			client := New(tt.apiKey).WithBaseURL(server.URL)

			// Test GetUploadURL
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
		analysisID string
		response   interface{}
		statusCode int
		wantErr    bool
	}{
		{
			name:       "successful response",
			apiKey:     "test-key",
			analysisID: "test-id",
			response: FileReport{
				Data: struct {
					Attributes struct {
						Status              string                     `json:"status"`
						LastAnalysisResults map[string]AnalysisResult `json:"last_analysis_results"`
					} `json:"attributes"`
				}{
					Attributes: struct {
						Status              string                     `json:"status"`
						LastAnalysisResults map[string]AnalysisResult `json:"last_analysis_results"`
					}{
						Status: "completed",
						LastAnalysisResults: map[string]AnalysisResult{
							"TestAV": {
								Category:   "undetected",
								EngineName: "TestAV",
							},
						},
					},
				},
			},
			statusCode: http.StatusOK,
			wantErr:    false,
		},
		{
			name:       "unauthorized",
			apiKey:     "invalid-key",
			analysisID: "test-id",
			response:   map[string]string{"error": "unauthorized"},
			statusCode: http.StatusUnauthorized,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Check request
				if r.Header.Get("x-apikey") != tt.apiKey {
					w.WriteHeader(http.StatusUnauthorized)
					json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
					return
				}

				// Send response
				w.WriteHeader(tt.statusCode)
				json.NewEncoder(w).Encode(tt.response)
			}))
			defer server.Close()

			// Create client with test server URL
			client := New(tt.apiKey).WithBaseURL(server.URL)

			// Test GetAnalysis
			report, err := client.GetAnalysis(context.Background(), tt.analysisID)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAnalysis() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && report == nil {
				t.Error("GetAnalysis() returned nil report")
			}
		})
	}
}