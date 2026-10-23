package operator

import "github.com/teddashh/AI-Intune/internal/store"

// Signins is shared by HTML and the read-only operator API.
func (s *Service) Signins() ([]store.SigninGroup, error) { return s.store.Signins() }
