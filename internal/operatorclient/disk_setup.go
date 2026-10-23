package operatorclient

import (
	"context"
	"fmt"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http"
)

func (c *Client) MachineDisks(ctx context.Context, id string) (store.MachineDisks, error) {
	var out store.MachineDisks
	if id == "" || len(id) > 256 {
		return out, fmt.Errorf("operator client: invalid machine ID")
	}
	req, err := c.newMachineOperatorRequest(ctx, http.MethodGet, id, "/disks", nil)
	if err != nil {
		return out, err
	}
	resp, err := c.doRawWithLimit(req, 1<<20, "1 MiB")
	if err != nil {
		return out, err
	}
	if resp.status != http.StatusOK {
		return out, fmt.Errorf("operator client: disk read returned HTTP %d", resp.status)
	}
	if err = validateMachineReadHeaders(resp.header); err != nil {
		return out, err
	}
	if err = decodeStrictJSONDocument(resp.body, "machine disks", &out); err != nil {
		return out, err
	}
	if out.Devices == nil || out.Jobs == nil {
		return out, fmt.Errorf("operator client: missing disk inventory")
	}
	for _, j := range out.Jobs {
		if err = j.Job.Validate(); err != nil {
			return store.MachineDisks{}, err
		}
		switch j.State {
		case "pending", "delivered", "done", "refused", "failed", "expired":
		default:
			return store.MachineDisks{}, fmt.Errorf("operator client: invalid disk job state")
		}
	}
	return out, nil
}
