package model

import "time"

// AuthHealth contains metadata only. OK means local evidence, not a provider test.
type AuthHealth struct {
	CLI           string     `json:"cli"`
	Slot          int        `json:"slot"`
	Account       string     `json:"account,omitempty"`
	Status        string     `json:"status"`
	Reason        string     `json:"reason"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
}

type SigninCommand struct {
	ID        string    `json:"id"`
	CLI       string    `json:"cli"`
	Slot      int       `json:"slot"`
	Operation string    `json:"operation"`
	ExpiresAt time.Time `json:"expires_at"`
	Code      string    `json:"code,omitempty"`
}

// SigninUpdate is the entire allowed projection of a login process's output.
type SigninUpdate struct {
	ID         string       `json:"id"`
	State      string       `json:"state"`
	URL        string       `json:"url,omitempty"`
	DeviceCode string       `json:"device_code,omitempty"`
	Reason     string       `json:"reason,omitempty"`
	Health     []AuthHealth `json:"health,omitempty"`
}
