package operatorclient

import (
	"context"
	"fmt"
	"net/url"

	"github.com/teddashh/AI-Intune/internal/store"
)

func (c *Client) Loops(ctx context.Context, machine string) (store.LoopsRead, error) {
	out := store.LoopsRead{}
	if len(machine) > 256 {
		return out, fmt.Errorf("invalid machine filter")
	}
	path := "/v1/operator/loops"
	if machine != "" {
		path += "?machine_id=" + url.QueryEscape(machine)
	}
	err := c.supervisionRead(ctx, path, &out)
	return out, err
}
