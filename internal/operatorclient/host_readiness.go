package operatorclient

import (
	"context"
	"fmt"
	"net/http"

	"github.com/teddashh/AI-Intune/internal/store"
)

func (c *Client) MachineReadiness(ctx context.Context, id string) (store.HostChecklist, error) {
	var out store.HostChecklist
	req, err := c.newMachineOperatorRequest(ctx, http.MethodGet, id, "/readiness", nil)
	if err != nil {
		return out, err
	}
	response, err := c.doRawWithLimit(req, 64<<10, "64 KiB")
	if err != nil {
		return out, err
	}
	if response.status != http.StatusOK {
		return out, fmt.Errorf("operator client: readiness read returned HTTP %d", response.status)
	}
	if err = validateMachineReadHeaders(response.header); err != nil {
		return out, err
	}
	if err = decodeStrictJSONDocument(response.body, "readiness", &out); err != nil {
		return out, err
	}
	if out.MachineID != id || len(out.Items) != 10 {
		return store.HostChecklist{}, fmt.Errorf("operator client: invalid readiness response")
	}
	return out, nil
}
