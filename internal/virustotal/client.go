package virustotal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	baseURL           = "https://www.virustotal.com/api/v3"
	uploadURLEndpoint = "/private/files/upload_url"
	analysesEndpoint  = "/private/analyses/%s"
	commentsEndpoint  = "/private/comments"
)

// Client represents a VirusTotal API client
type Client struct {
	apiKey     string
	httpClient *http.Client
}

// AnalysisStatus represents the status of a file analysis
type AnalysisStatus struct {
	ID     string
	Status string
	Issues []Issue
}

// Issue represents a detected issue by an antivirus engine
type Issue struct {
	Engine string
	Result string
}

// NewClient creates a new VirusTotal API client
func NewClient(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: time.Second * 30,
		},
	}
}

// GetUploadURL gets a URL for uploading large files
func (c *Client) GetUploadURL() (string, error) {
	req, err := http.NewRequest("GET", baseURL+uploadURLEndpoint, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("x-apikey", c.apiKey)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get upload URL: %s", resp.Status)
	}

	var result struct {
		Data string `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.Data, nil
}

// UploadFile uploads a file to VirusTotal
func (c *Client) UploadFile(filePath string, uploadURL string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return "", err
	}

	if _, err = io.Copy(part, file); err != nil {
		return "", err
	}
	writer.Close()

	req, err := http.NewRequest("POST", uploadURL, body)
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("x-apikey", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to upload file: %s", resp.Status)
	}

	var result struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.Data.ID, nil
}

// AddComment adds a comment to a file analysis
func (c *Client) AddComment(analysisID, comment string) error {
	data := map[string]string{
		"analysis_id": analysisID,
		"text":       comment,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", baseURL+commentsEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-apikey", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to add comment: %s", resp.Status)
	}

	return nil
}

// GetAnalysisStatus gets the current status of a file analysis
func (c *Client) GetAnalysisStatus(analysisID string) (*AnalysisStatus, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf(baseURL+analysesEndpoint, analysisID), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("x-apikey", c.apiKey)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get analysis status: %s", resp.Status)
	}

	var result struct {
		Data struct {
			Attributes struct {
				Status string `json:"status"`
				Results map[string]struct {
					Category string `json:"category"`
					Result   string `json:"result"`
				} `json:"last_analysis_results"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	status := &AnalysisStatus{
		ID:     analysisID,
		Status: result.Data.Attributes.Status,
	}

	for engine, res := range result.Data.Attributes.Results {
		if res.Category != "undetected" && res.Result != "" {
			status.Issues = append(status.Issues, Issue{
				Engine: engine,
				Result: res.Result,
			})
		}
	}

	return status, nil
}