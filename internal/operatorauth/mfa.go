package operatorauth

import "time"

const DefaultAdminMFAWindow = 12 * time.Hour
const DangerousMFAWindow = 5 * time.Minute

// MFAWithin rejects absent and future timestamps as well as expired proofs.
func MFAWithin(verified, now time.Time, window time.Duration) bool {
	return !verified.IsZero() && window > 0 && !verified.After(now) && now.Sub(verified) < window
}
