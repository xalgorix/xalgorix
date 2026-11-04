package agent

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/tools/httpclient"
)

// injectionPoint describes WHERE a verifier places its payload: the query string
// (default) or the request body (JSON or form-encoded). Body injection lets
// verify_sqli / verify_ssti reach parameters that live only in a POST/PUT/PATCH
// body — the ones probe_body_contract discovers — instead of only the URL query.
// It is shared by the injection verifiers so the body-vs-query choice behaves
// identically across them.
type injectionPoint struct {
	location string // "query" | "body"
	bodyType string // "json" | "form" (only meaningful for body)
	baseBody string // optional template the injected field is merged into
}

// resolveInjectionPoint reads the shared inject_in / body_type / base_body args.
func resolveInjectionPoint(args map[string]string) (injectionPoint, error) {
	loc := strings.ToLower(strings.TrimSpace(args["inject_in"]))
	if loc == "" {
		loc = "query"
	}
	if loc != "query" && loc != "body" {
		return injectionPoint{}, fmt.Errorf("inject_in must be 'query' or 'body'")
	}
	bt := strings.ToLower(strings.TrimSpace(args["body_type"]))
	if bt == "" {
		bt = "json"
	}
	if loc == "body" && bt != "json" && bt != "form" {
		return injectionPoint{}, fmt.Errorf("body_type must be 'json' or 'form'")
	}
	return injectionPoint{location: loc, bodyType: bt, baseBody: strings.TrimSpace(args["base_body"])}, nil
}

// defaultMethod returns the HTTP method to use. Body injection needs a body
// method, so an unset or GET/HEAD method becomes POST; query injection keeps the
// prior default of GET.
func (ip injectionPoint) defaultMethod(method string) string {
	m := strings.ToUpper(strings.TrimSpace(method))
	if ip.location == "body" {
		if m == "" || m == "GET" || m == "HEAD" {
			return "POST"
		}
		return m
	}
	if m == "" {
		return "GET"
	}
	return m
}

// buildRequest returns the URL, body, and content type that place value into
// param at this injection point. For the query location the body is empty; for
// the body location the param is merged into the JSON object or form map parsed
// from baseBody, so required sibling fields can ride along.
func (ip injectionPoint) buildRequest(u *url.URL, param, value string) (reqURL, body, contentType string, err error) {
	if ip.location == "query" {
		reqURL, err = withQueryParam(u, param, value)
		return reqURL, "", "", err
	}
	switch ip.bodyType {
	case "form":
		vals := url.Values{}
		if ip.baseBody != "" {
			parsed, perr := url.ParseQuery(ip.baseBody)
			if perr != nil {
				return "", "", "", fmt.Errorf("base_body is not valid form-encoded data: %w", perr)
			}
			vals = parsed
		}
		vals.Set(param, value)
		return u.String(), vals.Encode(), "application/x-www-form-urlencoded", nil
	default: // json
		obj := map[string]any{}
		if ip.baseBody != "" {
			if jerr := json.Unmarshal([]byte(ip.baseBody), &obj); jerr != nil {
				return "", "", "", fmt.Errorf("base_body is not a JSON object: %w", jerr)
			}
		}
		obj[param] = value
		raw, jerr := json.Marshal(obj)
		if jerr != nil {
			return "", "", "", jerr
		}
		return u.String(), string(raw), "application/json", nil
	}
}

// firstErr returns the first non-nil error, for compactly reporting which of
// several build steps failed.
func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// injectionReqLine renders a request line for ledger proof, appending a bounded
// body excerpt when one is present.
func injectionReqLine(method, reqURL, body string) string {
	if body == "" {
		return method + " " + reqURL
	}
	return method + " " + reqURL + "  (body: " + boundedText(body, 200) + ")"
}

// sendInjectionRequest issues one injection probe that may carry a body (the
// host was scope-checked by the caller), copying the shared auth headers map so
// it is not mutated. It returns the response body and the request line.
func (a *Agent) sendInjectionRequest(method, reqURL, body, contentType string, headers map[string]string) (respBody, reqLine string, err error) {
	reqLine = injectionReqLine(method, reqURL, body)
	h := headers
	if contentType != "" {
		h = make(map[string]string, len(headers)+1)
		for k, v := range headers {
			h[k] = v
		}
		h["Content-Type"] = contentType
	}
	resp, e := httpclient.SendRaw(httpclient.RawRequest{
		Method:          method,
		URL:             reqURL,
		Headers:         h,
		Body:            body,
		FollowRedirects: false,
		TimeoutSec:      30,
	})
	if e != nil {
		return "", reqLine, e
	}
	return string(resp.Body), reqLine, nil
}
