package operatorclient

import (
	"context"
	"errors"
	"fmt"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http"
	"net/url"
)

func (c *Client) DiskPolicyRead(ctx context.Context, id string) (any, error) {
	path := "/v1/operator/disk-ops/policies"
	if id != "" {
		path += "/" + url.PathEscape(id)
	}
	req, err := c.newOperatorRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	r, err := c.doRaw(req)
	if err != nil {
		return nil, err
	}
	if r.status != 200 {
		return nil, errors.New("disk policy read failed")
	}
	if err = validateSettingReadHeaders(r.header); err != nil {
		return nil, err
	}
	if id != "" {
		var out store.OpsPolicy
		err = decodeStrictJSONDocument(r.body, "disk policy", &out)
		return out, err
	}
	var out struct {
		Items []store.OpsPolicy `json:"items"`
	}
	err = decodeStrictJSONDocument(r.body, "disk policies", &out)
	return out.Items, err
}
func (c *Client) DiskPolicyUpsert(ctx context.Context, body store.DiskPolicyRequest, apply bool, key string) (store.DiskPolicyResult, error) {
	var out store.DiskPolicyResult
	path := "/v1/operator/disk-ops/policies/preview"
	if apply {
		path = "/v1/operator/disk-ops/policies"
		if !validSettingIdempotencyKey(key) || !validSHA256Digest(body.PreviewDigest) {
			return out, errors.New("invalid disk policy apply bindings")
		}
	}
	r, err := c.postSettingJSON(ctx, path, key, body)
	if err != nil {
		return out, err
	}
	replayed := false
	if apply {
		replayed, err = validateSettingWriteHeaders(r)
	} else if r.status != 200 {
		err = errors.New("disk policy preview failed")
	} else {
		err = validateSettingReadHeaders(r.header)
	}
	if err != nil {
		return out, err
	}
	err = decodeStrictJSONDocument(r.body, "disk policy receipt", &out)
	if err == nil && (!validSHA256Digest(out.PreviewDigest) || out.Replayed != replayed || (apply && out.PreviewDigest != body.PreviewDigest)) {
		err = errors.New("disk policy receipt mismatch")
	}
	return out, err
}

func (c *Client) DiskApprovalList(ctx context.Context, state, machine, operation string) ([]store.OpsApproval, error) {
	req, err := c.newOperatorRequest(ctx, http.MethodGet, "/v1/operator/disk-ops/approvals", nil)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	if state != "" {
		q.Set("state", state)
	}
	if machine != "" {
		q.Set("machine_id", machine)
	}
	if operation != "" {
		q.Set("operation", operation)
	}
	req.URL.RawQuery = q.Encode()
	r, err := c.doRaw(req)
	if err != nil {
		return nil, err
	}
	if r.status != 200 {
		return nil, errors.New("approval list failed")
	}
	if err = validateSettingReadHeaders(r.header); err != nil {
		return nil, err
	}
	var out struct {
		Items []store.OpsApproval `json:"items"`
	}
	err = decodeStrictJSONDocument(r.body, "disk approvals", &out)
	return out.Items, err
}
func (c *Client) DiskApprovalDecision(ctx context.Context, req store.OpsApprovalDecisionRequest, apply bool, key string) (store.OpsApprovalDecisionResult, error) {
	var out store.OpsApprovalDecisionResult
	path := "/v1/operator/disk-ops/approvals/" + url.PathEscape(req.ID) + "/decision"
	if !apply {
		path += "/preview"
	} else if !validSettingIdempotencyKey(key) || !validSHA256Digest(req.PreviewDigest) {
		return out, errors.New("invalid approval decision bindings")
	}
	r, err := c.postSettingJSON(ctx, path, key, req)
	if err != nil {
		return out, err
	}
	replayed := false
	if apply {
		replayed, err = validateSettingWriteHeaders(r)
	} else if r.status != 200 {
		err = errors.New("approval preview failed")
	} else {
		err = validateSettingReadHeaders(r.header)
	}
	if err != nil {
		return out, err
	}
	err = decodeStrictJSONDocument(r.body, "approval decision", &out)
	if err == nil && (!validSHA256Digest(out.PreviewDigest) || out.Replayed != replayed || out.Approval.ID != req.ID || (apply && out.PreviewDigest != req.PreviewDigest)) {
		err = errors.New("approval receipt mismatch")
	}
	return out, err
}

func (c *Client) DiskOpsStatus(ctx context.Context, id string) (store.DiskOpsStatus, error) {
	var out store.DiskOpsStatus
	req, err := c.newOperatorRequest(ctx, http.MethodGet, "/v1/operator/disk-ops/status/"+url.PathEscape(id), nil)
	if err != nil {
		return out, err
	}
	r, err := c.doRaw(req)
	if err != nil {
		return out, err
	}
	if r.status != 200 {
		return out, errors.New("disk status read failed")
	}
	if err = validateSettingReadHeaders(r.header); err != nil {
		return out, err
	}
	err = decodeStrictJSONDocument(r.body, "disk status", &out)
	return out, err
}

func (c *Client) DiskReport(ctx context.Context, id, cursor string, limit int) (store.DiskReportPage, error) {
	var out store.DiskReportPage
	path := "/v1/operator/disk-ops/reports/" + url.PathEscape(id) + "?cursor=" + url.QueryEscape(cursor) + "&limit=" + fmt.Sprint(limit)
	req, err := c.newOperatorRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return out, err
	}
	r, err := c.doRaw(req)
	if err != nil {
		return out, err
	}
	if r.status != 200 {
		return out, errors.New("disk report read failed")
	}
	if err = validateSettingReadHeaders(r.header); err != nil {
		return out, err
	}
	err = decodeStrictJSONDocument(r.body, "disk report", &out)
	return out, err
}
