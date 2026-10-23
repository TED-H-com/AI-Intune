package store

import "context"

// RefreshSessionMFA follows successful reauthentication. It never revives a
// session revoked or expired while the factors were being verified.
func (s *Store) RefreshSessionMFA(token, accountID string) error {
	now := s.nowFn()
	result, err := s.execWrite(context.Background(), "refresh_session_mfa", `UPDATE hub_sessions SET mfa_verified_at=? WHERE session_hash=? AND account_id=? AND revoked_at IS NULL AND julianday(idle_expires_at)>julianday(?) AND julianday(absolute_expires_at)>julianday(?) AND EXISTS(SELECT 1 FROM hub_accounts a JOIN hub_account_mfa m USING(account_id) WHERE a.account_id=? AND a.disabled_at IS NULL AND m.enabled_at IS NOT NULL)`, fmtTime(now), sessionHash(token), accountID, fmtTime(now), fmtTime(now), accountID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrSessionAuth
	}
	return nil
}
