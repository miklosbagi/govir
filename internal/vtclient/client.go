package vtclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	defaultBaseURL = "https://www.virustotal.com/api/v3"
	// GuiBaseURL is the base URL for VirusTotal's web interface
	GuiBaseURL = "https://www.virustotal.com/gui/file"
)

type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
	debug      bool
}

type ErrorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// UploadURLResponse represents the response from the upload URL endpoint
type UploadURLResponse struct {
	Data string `json:"data"` // The upload URL is returned directly as a string
}

type Analysis struct {
	Status            string
	Stats             Stats
	LastAnalysisStats LastAnalysisStats
	Detections        map[string]Detection
}

type Stats struct {
	Harmless   int
	Malicious  int
	Suspicious int
}

type AnalysisStats struct {
	Malicious        int `json:"malicious"`
	Suspicious       int `json:"suspicious"`
	Undetected       int `json:"undetected"`
	Harmless         int `json:"harmless"`
	Timeout          int `json:"timeout"`
	ConfirmedTimeout int `json:"confirmed-timeout"`
	Failure          int `json:"failure"`
	TypeUnsupported  int `json:"type-unsupported"`
}

type AnalysisResult struct {
	Category     string `json:"category"`
	EngineName   string `json:"engine_name"`
	EngineUpdate string `json:"engine_update"`
	Result       string `json:"result"`
}

type FileReport struct {
	Data struct {
		Attributes struct {
			Status  string                    `json:"status"`
			Stats   AnalysisStats             `json:"stats"`
			Results map[string]AnalysisResult `json:"results"`
		} `json:"attributes"`
		Links struct {
			Self string `json:"self"`
			Item string `json:"item"`
		} `json:"links"`
	} `json:"data"`
	Meta struct {
		FileInfo struct {
			SHA256 string `json:"sha256"`
			MD5    string `json:"md5"`
			SHA1   string `json:"sha1"`
			Size   int64  `json:"size"`
		} `json:"file_info"`
	} `json:"meta"`
}

// RetryConfig defines retry behavior
type RetryConfig struct {
	MaxAttempts       int
	InitialDelay      time.Duration
	MaxDelay          time.Duration
	BackoffMultiplier float64
}

// DefaultRetryConfig provides default retry settings
var DefaultRetryConfig = RetryConfig{
	MaxAttempts:       5,
	InitialDelay:      time.Second,
	MaxDelay:          time.Second * 30,
	BackoffMultiplier: 2.0,
}

// VTErrorCode represents specific VirusTotal API error codes
type VTErrorCode string

const (
	ErrAlreadyExists    VTErrorCode = "AlreadyExistsError"
	ErrWrongCredentials VTErrorCode = "WrongCredentialsError"
	ErrQuotaExceeded    VTErrorCode = "QuotaExceededError"
	ErrNotFound         VTErrorCode = "NotFoundError"
	ErrInvalidRequest   VTErrorCode = "InvalidRequestError"
	ErrUnknown          VTErrorCode = "UnknownError"
)

// VTError represents a VirusTotal API error
type VTError struct {
	Code       VTErrorCode
	Message    string
	StatusCode int
	Retryable  bool
}

func (e *VTError) Error() string {
	return fmt.Sprintf("%s: %s (HTTP %d)", e.Code, e.Message, e.StatusCode)
}

// IsAlreadyExists returns true if the error is an AlreadyExistsError
func (e *VTError) IsAlreadyExists() bool {
	return e.Code == ErrAlreadyExists
}

// IsQuotaExceeded returns true if the error is a QuotaExceededError
func (e *VTError) IsQuotaExceeded() bool {
	return e.Code == ErrQuotaExceeded
}

// IsNotFound returns true if the error is a NotFoundError
func (e *VTError) IsNotFound() bool {
	return e.Code == ErrNotFound
}

func isRetryableError(statusCode int) bool {
	return statusCode == http.StatusTooManyRequests ||
		statusCode == http.StatusServiceUnavailable ||
		statusCode == http.StatusGatewayTimeout ||
		statusCode == http.StatusBadGateway
}

func New(apiKey string) *Client {
	return &Client{
		apiKey:  apiKey,
		baseURL: defaultBaseURL,
		httpClient: &http.Client{
			Timeout: time.Minute * 5,
		},
		debug: false,
	}
}

// WithBaseURL sets a custom base URL for the client
func (c *Client) WithBaseURL(url string) *Client {
	c.baseURL = url
	return c
}

// WithDebug enables or disables debug logging
func (c *Client) WithDebug(debug bool) *Client {
	c.debug = debug
	return c
}

// debugLog logs a message only if debug mode is enabled
func (c *Client) debugLog(format string, v ...interface{}) {
	if c.debug {
		log.Printf(format, v...)
	}
}

func (c *Client) handleErrorResponse(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading error response: %w", err)
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(body, &errResp); err != nil {
		return &VTError{
			Code:       ErrUnknown,
			Message:    string(body),
			StatusCode: resp.StatusCode,
			Retryable:  isRetryableError(resp.StatusCode),
		}
	}

	return &VTError{
		Code:       VTErrorCode(errResp.Error.Code),
		Message:    errResp.Error.Message,
		StatusCode: resp.StatusCode,
		Retryable:  isRetryableError(resp.StatusCode),
	}
}

// prettyJSON formats JSON data with proper indentation
func prettyJSON(data []byte) string {
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, data, "", "  "); err != nil {
		return string(data) // Return original if prettification fails
	}
	return prettyJSON.String()
}

func (c *Client) GetUploadURL(ctx context.Context) (string, error) {
	url := fmt.Sprintf("%s/files/upload_url", c.baseURL)

	if c.debug {
		c.debugLog("Getting upload URL from: %s", url)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("x-apikey", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response: %v", err)
	}

	if c.debug {
		c.debugLog("Upload URL response:\n%s", prettyJSON(respBody))
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Data string `json:"data"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("error parsing response: %v", err)
	}

	if c.debug {
		c.debugLog("Got upload URL: %s", result.Data)
	}

	return result.Data, nil
}

func (c *Client) UploadFile(ctx context.Context, uploadURL string, path string) (*Analysis, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("error getting file info: %v", err)
	}

	if c.debug {
		c.debugLog("Uploading file: %s (size: %d bytes)", path, fileInfo.Size())
	}

	// Create multipart form
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Create form file field
	part, err := writer.CreateFormFile("file", filepath.Base(path))
	if err != nil {
		return nil, fmt.Errorf("error creating form file: %v", err)
	}

	// Copy file content
	written, err := io.Copy(part, file)
	if err != nil {
		return nil, fmt.Errorf("error copying file content: %v", err)
	}

	if c.debug {
		c.debugLog("Copied %d bytes to form", written)
	}

	// Close multipart writer
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("error closing writer: %v", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "POST", uploadURL, body)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("x-apikey", c.apiKey)

	if c.debug {
		c.debugLog("Making upload request to: %s", uploadURL)
		c.debugLog("Content-Type: %s", writer.FormDataContentType())
	}

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %v", err)
	}

	if c.debug {
		c.debugLog("Upload response status: %d", resp.StatusCode)
		c.debugLog("Upload response body:\n%s", prettyJSON(respBody))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Data struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"data"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("error parsing response: %v", err)
	}

	if c.debug {
		c.debugLog("Upload successful, analysis ID: %s", result.Data.ID)
	}

	return &Analysis{Status: "queued"}, nil
}

func (c *Client) GetAnalysis(ctx context.Context, hash string) (*Analysis, error) {
	url := fmt.Sprintf("%s/files/%s", c.baseURL, hash)

	if c.debug {
		c.debugLog("Getting analysis from: %s", url)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("x-apikey", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %v", err)
	}

	if c.debug {
		c.debugLog("Analysis response status: %d", resp.StatusCode)
		c.debugLog("Analysis response body:\n%s", prettyJSON(respBody))
	}

	if resp.StatusCode == http.StatusNotFound {
		if c.debug {
			c.debugLog("Analysis not found for hash: %s", hash)
		}
		return nil, fmt.Errorf("not found")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Data struct {
			Attributes struct {
				Status string `json:"status"`
				Stats  struct {
					Harmless   int `json:"harmless"`
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
				} `json:"stats"`
				LastAnalysisStats struct {
					Harmless   int `json:"harmless"`
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Undetected int `json:"undetected"`
					InProgress int `json:"in-progress"`
					Failure    int `json:"failure"`
				} `json:"last_analysis_stats"`
				LastAnalysisResults map[string]struct {
					Category   string `json:"category"`
					Result     string `json:"result"`
					Method     string `json:"method"`
					EngineType string `json:"engine_type"`
					EngineName string `json:"engine_name"`
				} `json:"last_analysis_results"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("error parsing response: %v", err)
	}

	if c.debug {
		c.debugLog("Analysis status: %s", result.Data.Attributes.Status)
		c.debugLog("Analysis stats - Harmless: %d, Malicious: %d, Suspicious: %d",
			result.Data.Attributes.Stats.Harmless,
			result.Data.Attributes.Stats.Malicious,
			result.Data.Attributes.Stats.Suspicious)
		c.debugLog("Last analysis stats - Harmless: %d, Malicious: %d, Suspicious: %d, Undetected: %d, InProgress: %d, Failure: %d",
			result.Data.Attributes.LastAnalysisStats.Harmless,
			result.Data.Attributes.LastAnalysisStats.Malicious,
			result.Data.Attributes.LastAnalysisStats.Suspicious,
			result.Data.Attributes.LastAnalysisStats.Undetected,
			result.Data.Attributes.LastAnalysisStats.InProgress,
			result.Data.Attributes.LastAnalysisStats.Failure)
	}

	detections := make(map[string]Detection)
	for name, res := range result.Data.Attributes.LastAnalysisResults {
		if res.Category == "malicious" || res.Category == "suspicious" {
			detections[name] = Detection{
				Category:   res.Category,
				Result:     res.Result,
				Method:     res.Method,
				EngineType: res.EngineType,
				EngineName: res.EngineName,
			}
		}
	}

	return &Analysis{
		Status: result.Data.Attributes.Status,
		Stats: Stats{
			Harmless:   result.Data.Attributes.Stats.Harmless,
			Malicious:  result.Data.Attributes.Stats.Malicious,
			Suspicious: result.Data.Attributes.Stats.Suspicious,
		},
		LastAnalysisStats: LastAnalysisStats{
			Harmless:   result.Data.Attributes.LastAnalysisStats.Harmless,
			Malicious:  result.Data.Attributes.LastAnalysisStats.Malicious,
			Suspicious: result.Data.Attributes.LastAnalysisStats.Suspicious,
			Undetected: result.Data.Attributes.LastAnalysisStats.Undetected,
			InProgress: result.Data.Attributes.LastAnalysisStats.InProgress,
			Failure:    result.Data.Attributes.LastAnalysisStats.Failure,
		},
		Detections: detections,
	}, nil
}

func (c *Client) AddComment(ctx context.Context, hash, comment string) error {
	url := fmt.Sprintf("%s/files/%s/comments", c.baseURL, hash)

	data := map[string]interface{}{
		"data": map[string]interface{}{
			"type": "comment",
			"attributes": map[string]interface{}{
				"text": comment,
			},
		},
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshaling comment: %v", err)
	}

	if c.debug {
		c.debugLog("Adding comment to %s", url)
		c.debugLog("Comment data:\n%s", prettyJSON(jsonData))
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("creating request: %v", err)
	}

	req.Header.Set("x-apikey", c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("making request: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %v", err)
	}

	if c.debug {
		c.debugLog("Comment response status: %d", resp.StatusCode)
		c.debugLog("Comment response body:\n%s", prettyJSON(respBody))
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

type LastAnalysisStats struct {
	Harmless   int
	Malicious  int
	Suspicious int
	Undetected int
	InProgress int
	Failure    int
}

type Detection struct {
	Category   string
	Result     string
	Method     string
	EngineType string `json:"engine_type"`
	EngineName string `json:"engine_name"`
}

type Comment struct {
	Data struct {
		Attributes struct {
			Text string `json:"text"`
		} `json:"attributes"`
	} `json:"data"`
}

func (c *Client) GetComments(ctx context.Context, hash string) ([]string, error) {
	url := fmt.Sprintf("%s/files/%s/comments", c.baseURL, hash)

	if c.debug {
		c.debugLog("Getting comments from: %s", url)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %v", err)
	}

	req.Header.Set("x-apikey", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %v", err)
	}

	if c.debug {
		c.debugLog("Comments response status: %d", resp.StatusCode)
		c.debugLog("Comments response body:\n%s", prettyJSON(respBody))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Data []struct {
			Attributes struct {
				Text string `json:"text"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %v", err)
	}

	comments := make([]string, 0, len(result.Data))
	for _, comment := range result.Data {
		comments = append(comments, comment.Attributes.Text)
	}

	return comments, nil
}
