package operatorclient

import (
	"context"
	"errors"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http"
	"net/url"
)

func (c *Client) DiskActionPreview(ctx context.Context, req store.DiskActionRequest) (store.DiskActionPreview, error) {
	var out store.DiskActionPreview
	r, e := c.postSettingJSON(ctx, "/v1/operator/disk-ops/actions/preview", "", req)
	if e != nil {
		return out, e
	}
	if r.status != 200 {
		return out, errors.New("action preview failed")
	}
	if e = validateSettingReadHeaders(r.header); e != nil {
		return out, e
	}
	e = decodeStrictJSONDocument(r.body, "action preview", &out)
	if e == nil && (!validSHA256Digest(out.Digest) || out.ManifestID == "" || out.Approval.ItemDigest != out.Digest || out.Approval.State != "pending") {
		e = errors.New("manifest preview binding mismatch")
	}
	return out, e
}
func (c *Client) DiskRestorePreview(ctx context.Context, req store.DiskRestoreRequest) (store.DiskActionPreview, error) {
	var out store.DiskActionPreview
	r, e := c.postSettingJSON(ctx, "/v1/operator/disk-ops/restores/preview", "", req)
	if e != nil {
		return out, e
	}
	if r.status != 200 {
		return out, errors.New("restore preview failed")
	}
	if e = validateSettingReadHeaders(r.header); e != nil {
		return out, e
	}
	e = decodeStrictJSONDocument(r.body, "restore preview", &out)
	if e == nil && (!validSHA256Digest(out.Digest) || out.ManifestID == "" || out.Approval.ItemDigest != out.Digest || out.Approval.State != "pending") {
		e = errors.New("manifest preview binding mismatch")
	}
	return out, e
}
func (c *Client) DiskActionDecide(ctx context.Context, req store.OpsApprovalDecisionRequest, key string, restore bool) (store.OpsApprovalDecisionResult, error) {
	var out store.OpsApprovalDecisionResult
	apply := req.PreviewDigest != ""
	if restore && (!apply || req.Decision != "approved") {
		return out, errors.New("invalid restore approval")
	}
	if apply && (!validSettingIdempotencyKey(key) || !validSHA256Digest(req.PreviewDigest)) {
		return out, errors.New("invalid disk action apply bindings")
	}
	path := "/v1/operator/disk-ops/actions/decide"
	if restore {
		path = "/v1/operator/disk-ops/restores"
	}
	r, e := c.postSettingJSON(ctx, path, key, req)
	if e != nil {
		return out, e
	}
	replayed := false
	if apply {
		replayed, e = validateSettingWriteHeaders(r)
	} else if r.status != 200 {
		e = errors.New("action decision preview failed")
	} else {
		e = validateSettingReadHeaders(r.header)
	}
	if e != nil {
		return out, e
	}
	e = decodeStrictJSONDocument(r.body, "action decision", &out)
	if e == nil && (!validSHA256Digest(out.PreviewDigest) || out.Replayed != replayed || out.Approval.ID != req.ID || (apply && (out.PreviewDigest != req.PreviewDigest || out.Approval.ItemDigest != req.ItemDigest))) {
		e = errors.New("action receipt mismatch")
	}
	return out, e
}
func (c *Client) DiskQuarantineList(ctx context.Context, machine string) ([]store.DiskQuarantineItem, error) {
	req, e := c.newOperatorRequest(ctx, http.MethodGet, "/v1/operator/disk-ops/quarantine/"+url.PathEscape(machine), nil)
	if e != nil {
		return nil, e
	}
	r, e := c.doRaw(req)
	if e != nil {
		return nil, e
	}
	if r.status != 200 {
		return nil, errors.New("quarantine read failed")
	}
	if e = validateSettingReadHeaders(r.header); e != nil {
		return nil, e
	}
	var out struct {
		Items []store.DiskQuarantineItem `json:"items"`
	}
	e = decodeStrictJSONDocument(r.body, "quarantine", &out)
	return out.Items, e
}
