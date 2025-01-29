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

const defaultBaseURL = "https://www.virustotal.com/api/v3"

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

type ScanResponse struct {
	Data struct {
		Type  string `json:"type"`
		ID    string `json:"id"`
		Links struct {
			Self string `json:"self"`
		} `json:"links"`
	} `json:"data"`
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
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/files/upload_url", nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("x-apikey", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("getting upload URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", c.handleErrorResponse(resp)
	}

	// Read and log the response body for debugging
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response body: %w", err)
	}
	c.debugLog("Upload URL response:\n%s", prettyJSON(body))

	var uploadResp UploadURLResponse
	if err := json.Unmarshal(body, &uploadResp); err != nil {
		return "", fmt.Errorf("decoding response: %w", err)
	}

	return uploadResp.Data, nil
}

func (c *Client) UploadFile(ctx context.Context, uploadURL, filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Use just the base name of the file for the form field
	filename := filepath.Base(filePath)
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return "", fmt.Errorf("creating form file: %w", err)
	}

	if _, err := io.Copy(part, file); err != nil {
		return "", fmt.Errorf("copying file: %w", err)
	}
	writer.Close()

	req, err := http.NewRequestWithContext(ctx, "POST", uploadURL, body)
	if err != nil {
		return "", fmt.Errorf("creating upload request: %w", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("x-apikey", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("uploading file: %w", err)
	}
	defer resp.Body.Close()

	// Read and log the response body for debugging
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response body: %w", err)
	}
	c.debugLog("Upload response:\n%s", prettyJSON(respBody))

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err != nil {
			return "", fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(respBody))
		}
		return "", fmt.Errorf("%s: %s", errResp.Error.Code, errResp.Error.Message)
	}

	var scanResp ScanResponse
	if err := json.Unmarshal(respBody, &scanResp); err != nil {
		return "", fmt.Errorf("decoding response: %w", err)
	}

	return scanResp.Data.ID, nil
}

func (c *Client) GetAnalysis(ctx context.Context, id string) (*FileReport, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/analyses/%s", c.baseURL, id), nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("x-apikey", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getting analysis: %w", err)
	}
	defer resp.Body.Close()

	// Read and log the response body for debugging
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	c.debugLog("Analysis response:\n%s", prettyJSON(body))

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if err := json.Unmarshal(body, &errResp); err != nil {
			return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(body))
		}
		return nil, fmt.Errorf("%s: %s", errResp.Error.Code, errResp.Error.Message)
	}

	var report FileReport
	if err := json.Unmarshal(body, &report); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &report, nil
}

func (c *Client) AddComment(ctx context.Context, id, comment string) error {
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
		return fmt.Errorf("marshaling comment: %w", err)
	}

	retryConfig := DefaultRetryConfig
	currentDelay := retryConfig.InitialDelay

	for attempt := 1; attempt <= retryConfig.MaxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "POST",
			fmt.Sprintf("%s/files/%s/comments", c.baseURL, id),
			bytes.NewBuffer(jsonData))
		if err != nil {
			return fmt.Errorf("creating request: %w", err)
		}

		req.Header.Set("x-apikey", c.apiKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("adding comment: %w", err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("reading response body: %w", err)
		}
		c.debugLog("Add comment response (attempt %d/%d):\n%s",
			attempt, retryConfig.MaxAttempts, prettyJSON(body))

		if resp.StatusCode == http.StatusOK {
			return nil
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

		vtErr := &VTError{
			Code:       VTErrorCode(errResp.Error.Code),
			Message:    errResp.Error.Message,
			StatusCode: resp.StatusCode,
			Retryable:  isRetryableError(resp.StatusCode),
		}

		// If it's an AlreadyExistsError, we can consider this a success
		if vtErr.IsAlreadyExists() {
			return nil
		}

		if !vtErr.Retryable || attempt == retryConfig.MaxAttempts {
			return vtErr
		}

		// Apply exponential backoff
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(currentDelay):
			currentDelay = time.Duration(float64(currentDelay) * retryConfig.BackoffMultiplier)
			if currentDelay > retryConfig.MaxDelay {
				currentDelay = retryConfig.MaxDelay
			}
		}
	}

	return fmt.Errorf("max retry attempts reached")
}
