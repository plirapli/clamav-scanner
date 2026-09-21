package classifier

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"scanner-service/analysis/evidence"
)

const (
	defaultTimeout = 10 * time.Second
	maxRetries     = 2
	maxResponse    = 1 << 20
	maxRetryAfter  = 30 * time.Second
)

type ClassifierDev struct {
	BaseURL      string
	APIKey       string
	Tier         string
	Labels       []string
	SendFilename bool
	Client       *http.Client
}

func NewClassifierDev(baseURL, apiKey, tier string, labels []string, sendFilename bool, timeout time.Duration) *ClassifierDev {
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	return &ClassifierDev{
		BaseURL:      strings.TrimRight(baseURL, "/"),
		APIKey:       apiKey,
		Tier:         tier,
		Labels:       labels,
		SendFilename: sendFilename,
		Client:       &http.Client{Timeout: timeout},
	}
}

type APIError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("classifier.dev returned %d (%s): %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("classifier.dev returned %d: %s", e.StatusCode, e.Message)
}

type requestBody struct {
	Input  string   `json:"input"`
	Labels []string `json:"labels"`
	Tier   string   `json:"tier,omitempty"`
}

type responseBody struct {
	Tier    string `json:"tier"`
	Model   string `json:"model"`
	Results []struct {
		Label      string             `json:"label"`
		Confidence *float64           `json:"confidence"`
		Scores     map[string]float64 `json:"scores"`
		Model      string             `json:"model"`
	} `json:"results"`
	Error string `json:"error"`
	Code  string `json:"code"`
}

func (c *ClassifierDev) Classify(ctx context.Context, ev evidence.FileEvidence) (Result, error) {
	payload, err := json.Marshal(requestBody{
		Input:  ev.ToText(c.SendFilename),
		Labels: c.Labels,
		Tier:   c.Tier,
	})
	if err != nil {
		return Result{}, err
	}

	var lastErr error
	var wait time.Duration

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if wait > 0 {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return Result{}, ctx.Err()
			}
		}

		result, retryAfter, err := c.do(ctx, payload)
		if err == nil {
			return result, nil
		}

		lastErr = err
		if !isRetryable(err) {
			return Result{}, err
		}

		wait = retryAfter
		if wait <= 0 {
			wait = time.Duration(attempt+1) * 500 * time.Millisecond
		}
	}

	return Result{}, lastErr
}

func (c *ClassifierDev) do(ctx context.Context, payload []byte) (Result, time.Duration, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL, bytes.NewReader(payload))
	if err != nil {
		return Result{}, 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if c.APIKey != "" {
		request.Header.Set("Authorization", "Bearer "+c.APIKey)
	}

	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}

	response, err := client.Do(request)
	if err != nil {
		return Result{}, 0, err
	}
	defer response.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(response.Body, maxResponse))

	if response.StatusCode != http.StatusOK {
		return Result{}, parseRetryAfter(response.Header.Get("Retry-After")), &APIError{
			StatusCode: response.StatusCode,
			Code:       responseCode(body),
			Message:    strings.TrimSpace(string(body)),
		}
	}

	var parsed responseBody
	if err := json.Unmarshal(body, &parsed); err != nil {
		return Result{}, 0, fmt.Errorf("invalid classifier response: %w", err)
	}
	if len(parsed.Results) == 0 {
		return Result{}, 0, errors.New("classifier returned no results")
	}

	first := parsed.Results[0]
	model := first.Model
	if model == "" {
		model = parsed.Model
	}

	return Result{
		Label:      first.Label,
		Confidence: first.Confidence,
		Scores:     first.Scores,
		Model:      model,
	}, 0, nil
}

func responseCode(body []byte) string {
	var parsed struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(body, &parsed)
	return parsed.Code
}

func parseRetryAfter(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}

	if seconds, err := strconv.Atoi(value); err == nil {
		wait := time.Duration(seconds) * time.Second
		if wait > maxRetryAfter {
			return maxRetryAfter
		}
		return wait
	}

	if date, err := http.ParseTime(value); err == nil {
		wait := time.Until(date)
		if wait < 0 {
			return 0
		}
		if wait > maxRetryAfter {
			return maxRetryAfter
		}
		return wait
	}

	return 0
}

func isRetryable(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusTooManyRequests || apiErr.StatusCode >= 500
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	return true
}
