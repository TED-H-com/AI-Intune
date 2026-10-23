package operatorclient

import (
	"context"
	"fmt"
	"net/http"

	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/store"
)

func (c *Client) JoinRequestsList(ctx context.Context) ([]store.JoinRequest, error) {
	req, err := c.newOperatorRequest(ctx, http.MethodGet, "/v1/operator/joins", nil)
	if err != nil {
		return nil, err
	}
	res, err := c.doRawWithLimit(req, 64<<10, "64 KiB")
	if err != nil {
		return nil, err
	}
	if res.status != 200 {
		return nil, fmt.Errorf("operator client: joins returned HTTP %d", res.status)
	}
	if err := validateMachineReadHeaders(res.header); err != nil {
		return nil, err
	}
	var out operator.JoinRequestsResult
	if err := decodeStrictJSONDocument(res.body, "joins", &out); err != nil {
		return nil, err
	}
	if len(out.Requests) > 20 {
		return nil, fmt.Errorf("operator client: too many join requests")
	}
	return out.Requests, nil
}
