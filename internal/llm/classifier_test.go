package llm

import (
	"testing"
)

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name      string
		rawErr    string
		wantClass ErrorClass
	}{
		{
			name:      "OpenAI Rate Limit TPM",
			rawErr:    `API returned 429: {"error": {"message": "Rate limit reached for model gpt-4o in organization org-123 on tokens per min (TPM)", "type": "tokens", "code": "rate_limit_exceeded"}}`,
			wantClass: ErrorClassRateLimit,
		},
		{
			name:      "OpenAI Quota Exhausted",
			rawErr:    `API returned 429: {"error": {"message": "You exceeded your current quota, please check your plan and billing details.", "type": "insufficient_quota", "code": "insufficient_quota"}}`,
			wantClass: ErrorClassQuotaExhausted,
		},
		{
			name:      "Anthropic Overloaded 529",
			rawErr:    `API returned 529: {"type": "error", "error": {"type": "overloaded_error", "message": "Anthropic's API is temporarily overloaded. Please try again later."}}`,
			wantClass: ErrorClassOverloaded,
		},
		{
			name:      "Anthropic Rate Limit",
			rawErr:    `API returned 429: {"type": "error", "error": {"type": "rate_limit_error", "message": "Number of request tokens has exceeded your per-minute rate limit"}}`,
			wantClass: ErrorClassRateLimit,
		},
		{
			name:      "Anthropic Balance Depleted",
			rawErr:    `API returned 400: {"type": "error", "error": {"type": "invalid_request_error", "message": "Your credit balance is too low to access the Anthropic API. Please go to Plans & Billing to upgrade or purchase credits."}}`,
			wantClass: ErrorClassQuotaExhausted,
		},
		{
			name:      "Google Gemini Resource Exhausted Rate Limit",
			rawErr:    `API returned 429: {"error": {"code": 429, "message": "Resource has been exhausted (e.g. check quota).", "status": "RESOURCE_EXHAUSTED"}}`,
			wantClass: ErrorClassQuotaExhausted,
		},
		{
			name:      "Context Window Overflow",
			rawErr:    `API returned 400: {"error": {"message": "This model's maximum context length is 128000 tokens. However, your messages resulted in 131072 tokens."}}`,
			wantClass: ErrorClassContextWindow,
		},
		{
			name:      "Auth Error",
			rawErr:    `API returned 401: {"error": {"message": "Incorrect API key provided: sk-invalid"}}`,
			wantClass: ErrorClassAuth,
		},
		{
			name:      "Generic Network Failure",
			rawErr:    `dial tcp 1.2.3.4:443: i/o timeout`,
			wantClass: ErrorClassGeneric,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyErrorString(tt.rawErr)
			if got.Class != tt.wantClass {
				t.Errorf("ClassifyErrorString() class = %v, want %v (msg: %s)", got.Class, tt.wantClass, got.Message)
			}
		})
	}
}
