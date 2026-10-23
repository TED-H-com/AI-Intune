package operatorclient

import (
	"context"
	"fmt"
	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http"
)

func (c *Client) HostProfile(ctx context.Context) (store.FleetHostProfile, error) {
	var out store.FleetHostProfile
	req, err := c.newOperatorRequest(ctx, http.MethodGet, "/v1/operator/host-profile", nil)
	if err != nil {
		return out, err
	}
	resp, err := c.doRawWithLimit(req, 1<<20, "1 MiB")
	if err != nil {
		return out, err
	}
	if resp.status != http.StatusOK {
		return out, fmt.Errorf("operator client: host setup read returned HTTP %d", resp.status)
	}
	if err = validateMachineReadHeaders(resp.header); err != nil {
		return out, err
	}
	if err = decodeStrictJSONDocument(resp.body, "host profile", &out); err != nil {
		return out, err
	}
	digest, err := out.Profile.Digest()
	if err != nil || digest != out.Digest {
		return store.FleetHostProfile{}, fmt.Errorf("operator client: invalid host profile digest")
	}
	if out.Hosts == nil {
		return store.FleetHostProfile{}, fmt.Errorf("operator client: missing host list")
	}
	seen := map[string]bool{}
	for _, h := range out.Hosts {
		if h.MachineID == "" || seen[h.MachineID] || (h.Status != "Up to date" && h.Status != "Waiting" && h.Status != "Failed") || h.Result != nil && !model.ValidHostApplyResult(h.Result) {
			return store.FleetHostProfile{}, fmt.Errorf("operator client: invalid host setup report")
		}
		seen[h.MachineID] = true
	}
	return out, nil
}
