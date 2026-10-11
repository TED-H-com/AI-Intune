package operatorclient

import (
	"context"
	"errors"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http"
	"net/url"
)

func (c *Client) ScheduleRead(ctx context.Context, id string) (any, error) {
	path := "/v1/operator/schedules"
	if id != "" {
		path += "/" + url.PathEscape(id)
	}
	req, e := c.newOperatorRequest(ctx, http.MethodGet, path, nil)
	if e != nil {
		return nil, e
	}
	r, e := c.doRaw(req)
	if e != nil {
		return nil, e
	}
	if r.status != 200 {
		return nil, errors.New("schedule read failed")
	}
	if e = validateSettingReadHeaders(r.header); e != nil {
		return nil, e
	}
	if id == "" {
		var out store.ScheduleListResponse
		e = decodeStrictJSONDocument(r.body, "schedules", &out)
		return out.Items, e
	}
	var out store.Schedule
	e = decodeStrictJSONDocument(r.body, "schedule", &out)

	return out, e
}
func (c *Client) ScheduleManage(ctx context.Context, body store.ScheduleRequest, operation string, apply bool, key string) (store.ScheduleResult, error) {
	var out store.ScheduleResult
	if operation != "upsert" && operation != "set-enabled" {
		return out, errors.New("invalid schedule operation")
	}
	phase := "preview"
	if apply {
		phase = "apply"
		if !validSettingIdempotencyKey(key) || !validSHA256Digest(body.PreviewDigest) {
			return out, errors.New("invalid apply coordinates")
		}
	}
	r, e := c.postSettingJSON(ctx, "/v1/operator/schedules/"+operation+"/"+phase, key, body)
	if e != nil {
		return out, e
	}
	replayed := false
	if apply {
		replayed, e = validateSettingWriteHeaders(r)
	} else if r.status != 200 {
		e = errors.New("schedule preview failed")
	} else {
		e = validateSettingReadHeaders(r.header)
	}
	if e != nil {
		return out, e
	}
	e = decodeStrictJSONDocument(r.body, "schedule", &out)
	if e == nil && (!validSHA256Digest(out.PreviewDigest) || out.Replayed != replayed || (apply && out.PreviewDigest != body.PreviewDigest)) {
		e = errors.New("schedule receipt mismatch")
	}
	return out, e
}
func (c *Client) ScheduleRunNow(ctx context.Context, id, key string) (any, error) {
	if !validSettingIdempotencyKey(key) {
		return nil, errors.New("idempotency key required")
	}
	r, e := c.postSettingJSON(ctx, "/v1/operator/schedules/"+url.PathEscape(id)+"/run-now", key, struct{}{})
	if e != nil {
		return nil, e
	}
	if r.status != 200 {
		return nil, errors.New("schedule run failed")
	}
	if e = validateJSONNoStoreResponse(r.header); e != nil {
		return nil, e
	}
	replayed, e := responseReplayEvidenceFromHeader(r.header)
	if e != nil {
		return nil, e
	}
	var out store.ScheduleRunNowResponse
	e = decodeStrictJSONDocument(r.body, "schedule run", &out)
	if e == nil && out.Replayed != replayed {
		e = errors.New("schedule replay receipt mismatch")
	}
	return out, e
}
