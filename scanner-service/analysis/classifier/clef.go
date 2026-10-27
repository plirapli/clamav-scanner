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

	// verdictQuestion is the id of the single Clef choice question asked per file.
	verdictQuestion = "verdict"
	verdictPrompt   = "This is a static-analysis summary of a file that ClamAV did not flag; the file was never executed. Judge it only by the indicators listed and pick the classification that fits best."
)

var ErrMissingCredentials = errors.New("clef: CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN are required")

// labelCriteria describes the default labels to Clef. The descriptions say
// what positive evidence each label needs; without that, Clef treats any
// unfamiliar binary as suspicious and any quiet one as benign. Labels without
// an entry are sent with a null description.
var labelCriteria = map[string]string{
	"benign":                "Indicators point to legitimate software or an ordinary document: for example a valid signature from an identifiable publisher, normal structure and imports, no packing, no injection or downloader APIs, no auto-executing or obfuscated content. Being unsigned is common for open-source tools and is not on its own a reason to doubt an otherwise clean file.",
	"suspicious":            "At least one concrete risk indicator is present (packing or a tampered header in an unsigned binary, process-injection, keylogging or downloader APIs, auto-executing macros or scripts, obfuscated commands) but the evidence is not conclusive.",
	"malicious":             "Several strong indicators together point to malware: for example a signature that does not match the file, packing combined with injection or downloader behaviour, or obfuscated auto-executing content that fetches or runs a payload.",
	"insufficient-evidence": "Too little information to judge, for example a small binary with almost no imports and no other structure, or contents that could not be inspected. Do not choose benign merely because no red flags were found.",
}

// Clef classifies evidence with Cloudflare Workers AI @cf/cloudflare/clef.
type Clef struct {
	BaseURL      string
	AccountID    string
	APIKey       string
	Model        string
	Labels       []string
	SendFilename bool
	Client       *http.Client
}

func NewClef(baseURL, accountID, apiKey, model string, labels []string, sendFilename bool, timeout time.Duration) *Clef {
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	return &Clef{
		BaseURL:      strings.TrimRight(baseURL, "/"),
		AccountID:    accountID,
		APIKey:       apiKey,
		Model:        model,
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
		return fmt.Sprintf("clef returned %d (%s): %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("clef returned %d: %s", e.StatusCode, e.Message)
}

type clefQuestion struct {
	Type         string         `json:"type"`
	Instructions string         `json:"instructions"`
	Criteria     map[string]any `json:"criteria"`
}

type requestBody struct {
	Model     string                  `json:"model"`
	State     string                  `json:"state"`
	Questions map[string]clefQuestion `json:"questions"`
}

type clefAnswer struct {
	Type          string             `json:"type"`
	Choice        string             `json:"choice"`
	Probabilities map[string]float64 `json:"probabilities"`
	Confidence    *float64           `json:"confidence"`
}

type responseBody struct {
	Success bool `json:"success"`
	Result  *struct {
		Model   string                `json:"model"`
		Answers map[string]clefAnswer `json:"answers"`
	} `json:"result"`
	Errors []cloudflareError `json:"errors"`
}

type cloudflareError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (c *Clef) endpoint() string {
	return fmt.Sprintf("%s/accounts/%s/ai/run/@cf/cloudflare/%s", c.BaseURL, c.AccountID, c.Model)
}

func (c *Clef) Classify(ctx context.Context, ev evidence.FileEvidence) (Result, error) {
	if c.AccountID == "" || c.APIKey == "" {
		return Result{}, ErrMissingCredentials
	}

	criteria := make(map[string]any, len(c.Labels))
	for _, label := range c.Labels {
		if description, ok := labelCriteria[label]; ok {
			criteria[label] = description
		} else {
			criteria[label] = nil
		}
	}

	payload, err := json.Marshal(requestBody{
		Model: c.Model,
		State: ev.ToText(c.SendFilename),
		Questions: map[string]clefQuestion{
			verdictQuestion: {Type: "choice", Instructions: verdictPrompt, Criteria: criteria},
		},
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

func (c *Clef) do(ctx context.Context, payload []byte) (Result, time.Duration, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(), bytes.NewReader(payload))
	if err != nil {
		return Result{}, 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+c.APIKey)

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
		return Result{}, parseRetryAfter(response.Header.Get("Retry-After")), apiError(response.StatusCode, body)
	}

	var parsed responseBody
	if err := json.Unmarshal(body, &parsed); err != nil {
		return Result{}, 0, fmt.Errorf("invalid clef response: %w", err)
	}
	if !parsed.Success || parsed.Result == nil {
		return Result{}, 0, apiError(response.StatusCode, body)
	}

	answer, ok := parsed.Result.Answers[verdictQuestion]
	if !ok || answer.Choice == "" {
		return Result{}, 0, errors.New("clef returned no verdict answer")
	}

	// Confidence is the probability of the chosen label, matching the policy's
	// VERDICT_BLOCK_CONFIDENCE semantics. Clef's own confidence is derived from
	// the whole distribution and is only a fallback.
	confidence := answer.Confidence
	if probability, ok := answer.Probabilities[answer.Choice]; ok {
		confidence = &probability
	}

	model := parsed.Result.Model
	if model == "" {
		model = c.Model
	}

	return Result{
		Label:      answer.Choice,
		Confidence: confidence,
		Scores:     answer.Probabilities,
		Model:      model,
	}, 0, nil
}

func apiError(status int, body []byte) *APIError {
	apiErr := &APIError{StatusCode: status, Message: strings.TrimSpace(string(body))}

	var parsed struct {
		Errors []cloudflareError `json:"errors"`
	}
	if json.Unmarshal(body, &parsed) == nil && len(parsed.Errors) > 0 {
		apiErr.Code = strconv.Itoa(parsed.Errors[0].Code)
		apiErr.Message = parsed.Errors[0].Message
	}
	return apiErr
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
