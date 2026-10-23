package operatorclient

import (
	"context"
	"github.com/teddashh/AI-Intune/internal/store"
)

func (c *Client) Signins(ctx context.Context) ([]store.SigninGroup, error) {
	v := []store.SigninGroup{}
	e := c.supervisionRead(ctx, "/v1/operator/signins", &v)
	return v, e
}
