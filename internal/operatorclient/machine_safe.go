package operatorclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"

	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/scrubguard"
)

// MachineSafe reads the bot-safe detail/evidence projection. It intentionally
// does not decode Projection back into the human DTOs: the scrubbed JSON tree is
// the contract bots receive.
func (c *Client) MachineSafe(ctx context.Context, machineID string) (operator.MachineSafeResult, error) {
	req, err := c.newMachineOperatorRequest(ctx, http.MethodGet, machineID, "/safe", nil)
	if err != nil {
		return operator.MachineSafeResult{}, err
	}
	response, err := c.doRawWithLimit(req, 8<<20, "8 MiB")
	if err != nil {
		return operator.MachineSafeResult{}, err
	}
	if response.status != http.StatusOK {
		return operator.MachineSafeResult{}, fmt.Errorf("operator client: scrubbed machine detail returned HTTP %d", response.status)
	}
	if err := validateMachineReadHeaders(response.header); err != nil {
		return operator.MachineSafeResult{}, err
	}
	var result operator.MachineSafeResult
	if err := decodeStrictJSONDocument(response.body, "scrubbed machine detail", &result); err != nil {
		return operator.MachineSafeResult{}, err
	}
	if err := validateMachineSafeResult(result); err != nil {
		return operator.MachineSafeResult{}, err
	}
	return result, nil
}

func validateMachineSafeResult(result operator.MachineSafeResult) error {
	if result.SchemaVersion != 1 || result.ScrubberVersion != 1 || result.Projection == nil || result.Redactions < 0 || result.Redacted != (result.Redactions > 0) || result.RedactionFlags == nil {
		return errors.New("operator client: scrubbed machine detail metadata is inconsistent")
	}
	known := map[string]bool{
		scrubguard.FlagAssignment: true, scrubguard.FlagAuthorization: true,
		scrubguard.FlagEntropy: true, scrubguard.FlagJWT: true, scrubguard.FlagPEM: true,
		scrubguard.FlagProviderToken: true, scrubguard.FlagURLCredentials: true,
	}
	if !sort.StringsAreSorted(result.RedactionFlags) || (result.Redactions == 0) != (len(result.RedactionFlags) == 0) {
		return errors.New("operator client: scrubbed machine detail flags are inconsistent")
	}
	for i, flag := range result.RedactionFlags {
		if !known[flag] || (i > 0 && result.RedactionFlags[i-1] == flag) {
			return errors.New("operator client: scrubbed machine detail contains an invalid flag")
		}
	}
	return nil
}
