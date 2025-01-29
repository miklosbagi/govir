package scanner

import (
	"context"
	"sync"
	"testing"
	"time"

	"govir/internal/vtclient"
)

type mockClient struct {
	uploadURL  string
	analysisID string
	report     *vtclient.FileReport
	err        error
	callCount  int
	mu         sync.Mutex
}

func (m *mockClient) GetUploadURL(ctx context.Context) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return m.uploadURL, nil
}

func (m *mockClient) UploadFile(ctx context.Context, uploadURL, filepath string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return m.analysisID, nil
}

func (m *mockClient) GetAnalysis(ctx context.Context, id string) (*vtclient.FileReport, error) {
	if m.err != nil {
		return nil, m.err
	}

	m.mu.Lock()
	m.callCount++
	count := m.callCount
	m.mu.Unlock()

	// Simulate status change after first call
	if count == 1 {
		return &vtclient.FileReport{
			Data: struct {
				Attributes struct {
					Status              string                             `json:"status"`
					LastAnalysisResults map[string]vtclient.AnalysisResult `json:"last_analysis_results"`
				} `json:"attributes"`
			}{
				Attributes: struct {
					Status              string                             `json:"status"`
					LastAnalysisResults map[string]vtclient.AnalysisResult `json:"last_analysis_results"`
				}{
					Status: "in_progress",
				},
			},
		}, nil
	}

	return m.report, nil
}

func (m *mockClient) AddComment(ctx context.Context, id, comment string) error {
	return m.err
}

func TestScanner_ScanFile(t *testing.T) {
	tests := []struct {
		name     string
		client   *mockClient
		filePath string
		wantErr  bool
	}{
		{
			name: "successful scan - clean file",
			client: &mockClient{
				uploadURL:  "https://upload.virustotal.com/test",
				analysisID: "test-id",
				report: &vtclient.FileReport{
					Data: struct {
						Attributes struct {
							Status              string                             `json:"status"`
							LastAnalysisResults map[string]vtclient.AnalysisResult `json:"last_analysis_results"`
						} `json:"attributes"`
					}{
						Attributes: struct {
							Status              string                             `json:"status"`
							LastAnalysisResults map[string]vtclient.AnalysisResult `json:"last_analysis_results"`
						}{
							Status: "completed",
							LastAnalysisResults: map[string]vtclient.AnalysisResult{
								"TestAV": {
									Category:   "undetected",
									EngineName: "TestAV",
									Result:     "",
								},
							},
						},
					},
				},
			},
			filePath: "testfile.exe",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(tt.client)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			err := s.ScanFile(ctx, tt.filePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("Scanner.ScanFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
