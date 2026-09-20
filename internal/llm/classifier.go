package llm

import (
	"strings"
)

// ErrorClass represents the semantic categorization of an LLM provider error.
type ErrorClass string

const (
	// ErrorClassRateLimit represents temporary per-minute or per-day rate limits (RPM / TPM).
	ErrorClassRateLimit ErrorClass = "rate_limit"

	// ErrorClassQuotaExhausted represents exhausted account balance, credit limits, or billing locks.
	// Unlike standard rate limits, this will NOT resolve with transient backoff.
	ErrorClassQuotaExhausted ErrorClass = "quota_exhausted"

	// ErrorClassOverloaded represents provider-side capacity overload (e.g. Anthropic HTTP 529).
	ErrorClassOverloaded ErrorClass = "overloaded"

	// ErrorClassContextWindow represents prompt length / token limit exceeding context window.
	ErrorClassContextWindow ErrorClass = "context_window"

	// ErrorClassAuth represents invalid API key, unauthenticated, or permission denied.
	ErrorClassAuth ErrorClass = "auth"

	// ErrorClassGeneric represents other unclassified or transient network errors.
	ErrorClassGeneric ErrorClass = "generic"
)

// ClassifiedError holds the error class and a descriptive detail message.
type ClassifiedError struct {
	Class   ErrorClass
	Message string
}

// ClassifyError inspects an LLM error and classifies it.
func ClassifyError(err error) ClassifiedError {
	if err == nil {
		return ClassifiedError{Class: ErrorClassGeneric}
	}
	return ClassifyErrorString(err.Error())
}

// ClassifyErrorString classifies an error string from an LLM call.
func ClassifyErrorString(rawErr string) ClassifiedError {
	errStr := strings.ToLower(rawErr)

	// 1. Context Window Overflow (takes precedence over generic 400s)
	if isContextWindowError(errStr) {
		return ClassifiedError{
			Class:   ErrorClassContextWindow,
			Message: "Context window overflow (prompt exceeds maximum model token limit)",
		}
	}

	// 2. Quota / Credit Exhaustion
	// Note: Quota errors sometimes return HTTP 429, HTTP 402, or HTTP 400 with a billing/quota body.
	if strings.Contains(errStr, "insufficient_quota") ||
		strings.Contains(errStr, "quota exceeded") ||
		strings.Contains(errStr, "exceeded your current quota") ||
		strings.Contains(errStr, "credit balance is too low") ||
		strings.Contains(errStr, "insufficient credits") ||
		strings.Contains(errStr, "out of credits") ||
		strings.Contains(errStr, "billing account") ||
		strings.Contains(errStr, "payment required") ||
		strings.Contains(errStr, "http 402") ||
		strings.Contains(errStr, "api returned 402") ||
		strings.Contains(errStr, "usage limit reached") ||
		strings.Contains(errStr, "plan limit exceeded") ||
		(strings.Contains(errStr, "resource_exhausted") && strings.Contains(errStr, "quota")) {
		return ClassifiedError{
			Class:   ErrorClassQuotaExhausted,
			Message: "LLM provider quota or credit balance exhausted (check account billing)",
		}
	}

	// 3. Provider Overloaded (HTTP 529 or overloaded message)
	if apiErrorHasStatus(errStr, 529) ||
		strings.Contains(errStr, "529") ||
		strings.Contains(errStr, "overloaded_error") ||
		strings.Contains(errStr, "engine is currently overloaded") ||
		strings.Contains(errStr, "temporarily overloaded") ||
		strings.Contains(errStr, "provider is overloaded") ||
		strings.Contains(errStr, "server is overloaded") ||
		strings.Contains(errStr, "upstream capacity exceeded") ||
		strings.Contains(errStr, "model is overloaded") {
		return ClassifiedError{
			Class:   ErrorClassOverloaded,
			Message: "LLM provider is temporarily overloaded (upstream capacity saturated)",
		}
	}

	// 4. Rate Limited (RPM / TPM)
	if isRateLimitError(errStr) {
		return ClassifiedError{
			Class:   ErrorClassRateLimit,
			Message: "LLM provider rate limit exceeded (requests or tokens per minute)",
		}
	}

	// 5. Auth / Permission errors
	if isNonRetryableLLMError(errStr) {
		return ClassifiedError{
			Class:   ErrorClassAuth,
			Message: "LLM provider authentication or permission error",
		}
	}

	return ClassifiedError{
		Class:   ErrorClassGeneric,
		Message: rawErr,
	}
}
