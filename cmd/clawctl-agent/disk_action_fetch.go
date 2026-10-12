package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
)

func (executor scriptExecutor) fetchDiskGrant(ctx context.Context, job, id, digest string) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	endpoint := strings.TrimRight(executor.hubURL, "/") + "/v1/ops-manifests/" + url.PathEscape(id) + "?" + url.Values{"job_id": {job}, "digest": {digest}}.Encode()
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid disk grant request")
	}
	req.Header.Set("Authorization", "Bearer "+executor.token)
	client := *httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return fmt.Errorf("disk grant redirects refused") }
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("disk grant request unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("disk grant request denied (%d)", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (3<<20)+1))
	if err != nil || len(raw) > 3<<20 || validateUniqueJSONFields(raw) != nil {
		return nil, fmt.Errorf("invalid disk grant response")
	}
	var grant scriptcatalog.SignedDiskGrant
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&grant) != nil || len(grant.Payload) == 0 || len(grant.Signature) == 0 {
		return nil, fmt.Errorf("invalid disk grant envelope")
	}
	return raw, nil
}
