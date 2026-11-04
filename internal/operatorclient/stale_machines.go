package operatorclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/store"
)

func (c *Client) StaleMachineCandidates(ctx context.Context, cursor string) (operator.StaleMachineReview, error) {
	path := "/v1/operator/stale-machines"
	if cursor != "" {
		if _, err := operator.DecodeStaleMachineCursor(cursor); err != nil {
			return operator.StaleMachineReview{}, err
		}
		path += "?cursor=" + url.QueryEscape(cursor)
	}
	req, err := c.newOperatorRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return operator.StaleMachineReview{}, err
	}
	res, err := c.doRawWithLimit(req, 4<<20, "4 MiB")
	if err != nil {
		return operator.StaleMachineReview{}, err
	}
	if res.status != http.StatusOK {
		return operator.StaleMachineReview{}, fmt.Errorf("operator client: stale machines returned HTTP %d", res.status)
	}
	if err := validateMachineReadHeaders(res.header); err != nil {
		return operator.StaleMachineReview{}, err
	}
	var out operator.StaleMachineReview
	if err := decodeStrictJSONDocument(res.body, "stale machines", &out); err != nil {
		return operator.StaleMachineReview{}, err
	}
	if err := validateStaleMachineReview(out, cursor); err != nil {
		return operator.StaleMachineReview{}, err
	}
	return out, nil
}

func validateStaleMachineReview(out operator.StaleMachineReview, cursor string) error {
	bad := errors.New("operator client: invalid stale machine evidence")
	if out.Consistency != operator.StaleMachineReviewConsistency || out.Truncated != (out.NextCursor != nil) || out.SchemaVersion != 1 || out.Limit != operator.StaleMachineReviewLimit || out.Items == nil || len(out.Items) > out.Limit || (out.Truncated && len(out.Items) != out.Limit) {
		return bad
	}
	if err := validateMachineEvaluationTime(out.EvaluatedAt); err != nil {
		return err
	}
	if cursor != "" && len(out.Items) > 0 {
		after, err := operator.DecodeStaleMachineCursor(cursor)
		first := out.Items[0]
		if err != nil || first.CreatedAt.Before(after.CreatedAt) || (first.CreatedAt.Equal(after.CreatedAt) && first.MachineID <= after.MachineID) {
			return bad
		}
	}
	if out.NextCursor != nil {
		next, err := operator.DecodeStaleMachineCursor(*out.NextCursor)
		last := out.Items[len(out.Items)-1]
		if err != nil || !next.CreatedAt.Equal(last.CreatedAt) || next.MachineID != last.MachineID {
			return bad
		}
	}
	seen := map[string]bool{}
	for i, item := range out.Items {
		if validateMachineClientText("id", item.MachineID, 256) != nil || seen[item.MachineID] || item.CreatedAt.IsZero() || item.CreatedAt.After(out.EvaluatedAt.Add(-time.Hour)) {
			return bad
		}
		seen[item.MachineID] = true
		for _, text := range []string{item.DisplayName, item.Hostname} {
			if len(text) > 256 || !utf8.ValidString(text) || strings.IndexFunc(text, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) >= 0 {
				return bad
			}
		}
		if strings.TrimSpace(item.DisplayName) == "" {
			return bad
		}
		if i > 0 {
			prev := out.Items[i-1]
			if prev.CreatedAt.After(item.CreatedAt) || (prev.CreatedAt.Equal(item.CreatedAt) && prev.MachineID >= item.MachineID) {
				return bad
			}
		}
		if len(item.Branches) < 1 || len(item.Branches) > 2 {
			return bad
		}
		duplicate, abandoned := false, false
		for _, branch := range item.Branches {
			switch branch {
			case store.StaleMachineDuplicateOfActive:
				if duplicate || abandoned {
					return bad
				}
				duplicate = true
			case store.StaleMachineAbandoned24h:
				if abandoned || item.CreatedAt.After(out.EvaluatedAt.Add(-24*time.Hour)) {
					return bad
				}
				abandoned = true
			default:
				return bad
			}
		}
		if abandoned != !item.CreatedAt.After(out.EvaluatedAt.Add(-24*time.Hour)) {
			return bad
		}
		if item.DuplicateOf == nil || len(item.DuplicateOf) > out.Limit || (item.RelatedTruncated && len(item.DuplicateOf) != out.Limit) || (!duplicate && (len(item.DuplicateOf) != 0 || item.RelatedTruncated)) {
			return bad
		}
		for j, id := range item.DuplicateOf {
			if validateMachineClientText("related id", id, 256) != nil || id == item.MachineID || (j > 0 && item.DuplicateOf[j-1] >= id) {
				return bad
			}
		}
	}
	return nil
}
