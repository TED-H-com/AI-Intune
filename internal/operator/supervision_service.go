package operator

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

const (
	SupervisionCacheTTL         = 30 * time.Second
	SupervisionWaitBudget       = 100 * time.Millisecond
	SupervisionMaxComputations  = 2
	SupervisionCacheEntries     = 32
	SupervisionPrincipalEntries = 1024
	SupervisionRateBurst        = 10
	SupervisionRatePerSecond    = 0.5 // Thirty requests/minute; shared across routes and cache hits.
)

var (
	ErrSupervisionBusy            = errors.New("supervision computations busy")
	ErrSupervisionRateLimited     = errors.New("supervision principal rate limited")
	ErrSupervisionSubjectRequired = errors.New("authenticated supervision subject required")
)

type supervisionBackend interface {
	JobsSummary(context.Context, SupervisionFilter, time.Time) (JobsSummary, error)
	ApprovalsSummary(context.Context, string, time.Time) (ApprovalsSummary, error)
	HubStatus(context.Context, string, time.Time, time.Time) (HubStatus, error)
}

type supervisionKey struct {
	operation string
	filter    SupervisionFilter
}
type supervisionCacheEntry struct {
	at      time.Time
	payload json.RawMessage
}
type supervisionPrincipalBudget struct {
	at     time.Time
	tokens float64
}

// SupervisionService is process-owned, shared by all three HTTP/MCP reads.
// Only the authenticated adapter supplies subject. The cache is principal-
// independent because these view DTOs do not contain principal-specific data.
// Encoded entries are immutable; each caller receives its own byte slice.
type SupervisionService struct {
	backend    supervisionBackend
	version    string
	startedAt  time.Time
	now        func() time.Time
	waitBudget time.Duration
	mu         sync.Mutex
	cache      map[supervisionKey]supervisionCacheEntry
	flights    map[supervisionKey]chan struct{}
	principals map[string]supervisionPrincipalBudget
	slots      chan struct{}
}

func NewSupervisionService(backend *Service, version string, startedAt time.Time) *SupervisionService {
	return &SupervisionService{backend: backend, version: version, startedAt: startedAt,
		now: func() time.Time { return time.Now().UTC() }, waitBudget: SupervisionWaitBudget,
		cache: make(map[supervisionKey]supervisionCacheEntry), flights: make(map[supervisionKey]chan struct{}),
		principals: make(map[string]supervisionPrincipalBudget), slots: make(chan struct{}, SupervisionMaxComputations)}
}

func (s *SupervisionService) JobsSummary(ctx context.Context, subject string, f SupervisionFilter) (json.RawMessage, error) {
	if err := ValidateSupervisionFilter(f); err != nil {
		return nil, err
	}
	// A machine filter always produces machine groups, independent of the
	// explicit per_machine spelling. URL ordering is absent from the key.
	if f.MachineID != "" {
		f.PerMachine = true
	}
	return s.read(ctx, subject, supervisionKey{operation: "jobs", filter: f}, func(ctx context.Context, at time.Time) (any, error) { return s.backend.JobsSummary(ctx, f, at) })
}
func (s *SupervisionService) ApprovalsSummary(ctx context.Context, subject, window string) (json.RawMessage, error) {
	f := SupervisionFilter{Window: window}
	if err := ValidateSupervisionFilter(f); err != nil {
		return nil, err
	}
	return s.read(ctx, subject, supervisionKey{operation: "approvals", filter: f}, func(ctx context.Context, at time.Time) (any, error) {
		return s.backend.ApprovalsSummary(ctx, window, at)
	})
}
func (s *SupervisionService) HubStatus(ctx context.Context, subject string) (json.RawMessage, error) {
	return s.read(ctx, subject, supervisionKey{operation: "status"}, func(ctx context.Context, at time.Time) (any, error) {
		return s.backend.HubStatus(ctx, s.version, s.startedAt, at)
	})
}

// Admission runs before cache lookup, so a hot key cannot bypass the quota.
// At capacity new subjects fail closed; only fully idle budgets are removed.
// Active callers cannot reset their quota by churning identities.
func (s *SupervisionService) admit(subject string, now time.Time) error {
	if subject == "" {
		return ErrSupervisionSubjectRequired
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.principals[subject]
	if !ok {
		if len(s.principals) >= SupervisionPrincipalEntries {
			for key, v := range s.principals {
				if now.Sub(v.at) >= time.Minute {
					delete(s.principals, key)
				}
			}
			if len(s.principals) >= SupervisionPrincipalEntries {
				return ErrSupervisionRateLimited
			}
		}
		b = supervisionPrincipalBudget{at: now, tokens: SupervisionRateBurst}
	}
	if now.After(b.at) {
		b.tokens = min(float64(SupervisionRateBurst), b.tokens+now.Sub(b.at).Seconds()*SupervisionRatePerSecond)
		b.at = now
	}
	if b.tokens < 1 {
		s.principals[subject] = b
		return ErrSupervisionRateLimited
	}
	b.tokens--
	s.principals[subject] = b
	return nil
}

func (s *SupervisionService) read(ctx context.Context, subject string, key supervisionKey, compute func(context.Context, time.Time) (any, error)) (json.RawMessage, error) {
	if ctx == nil {
		return nil, ErrInvalidSupervision
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.admit(subject, s.now()); err != nil {
		return nil, err
	}
	wait, cancel := context.WithTimeout(ctx, s.waitBudget)
	defer cancel()
	for {
		s.mu.Lock()
		if entry, ok := s.freshEntry(key, s.now()); ok {
			s.mu.Unlock()
			return append(json.RawMessage(nil), entry.payload...), nil
		}
		flight := s.flights[key]
		s.mu.Unlock()
		if flight != nil {
			if err := waitForSupervision(wait, ctx, flight); err != nil {
				return nil, err
			}
			continue
		}
		select {
		case s.slots <- struct{}{}:
		case <-wait.Done():
			return nil, supervisionWaitError(ctx)
		}
		if wait.Err() != nil {
			<-s.slots
			return nil, supervisionWaitError(ctx)
		}
		// Recheck while owning a slot: another request may have filled the
		// cache or started the same key between our lookup and admission.
		s.mu.Lock()
		if entry, ok := s.freshEntry(key, s.now()); ok {
			s.mu.Unlock()
			<-s.slots
			return append(json.RawMessage(nil), entry.payload...), nil
		}
		flight = s.flights[key]
		if flight != nil {
			s.mu.Unlock()
			<-s.slots
			if err := waitForSupervision(wait, ctx, flight); err != nil {
				return nil, err
			}
			continue
		}
		flight = make(chan struct{})
		s.flights[key] = flight
		s.mu.Unlock()
		return s.compute(ctx, key, flight, compute)
	}
}

// Caller holds mu. Cache misses expire immediately rather than serve stale data.
func (s *SupervisionService) freshEntry(key supervisionKey, now time.Time) (supervisionCacheEntry, bool) {
	entry, ok := s.cache[key]
	if ok && !now.Before(entry.at) && now.Sub(entry.at) < SupervisionCacheTTL {
		return entry, true
	}
	if ok {
		delete(s.cache, key)
	}
	return supervisionCacheEntry{}, false
}

func (s *SupervisionService) compute(ctx context.Context, key supervisionKey, flight chan struct{}, compute func(context.Context, time.Time) (any, error)) (json.RawMessage, error) {
	defer func() { s.mu.Lock(); delete(s.flights, key); close(flight); s.mu.Unlock(); <-s.slots }()
	result, err := compute(ctx, s.now())
	if err != nil {
		return nil, err
	}
	at := s.now()
	switch r := result.(type) {
	case JobsSummary:
		r.CachedAt = &at
		result = r
	case ApprovalsSummary:
		r.CachedAt = &at
		result = r
	case HubStatus:
		r.CachedAt = &at
		result = r
	default:
		return nil, errors.New("invalid supervision result type")
	}
	payload, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	for k, v := range s.cache {
		if at.Sub(v.at) >= SupervisionCacheTTL {
			delete(s.cache, k)
		}
	}
	if len(s.cache) >= SupervisionCacheEntries {
		var oldest supervisionKey
		var oldestAt time.Time
		for k, v := range s.cache {
			if oldestAt.IsZero() || v.at.Before(oldestAt) {
				oldest = k
				oldestAt = v.at
			}
		}
		delete(s.cache, oldest)
	}
	s.cache[key] = supervisionCacheEntry{at: at, payload: payload}
	s.mu.Unlock()
	return append(json.RawMessage(nil), payload...), nil
}

func waitForSupervision(wait, caller context.Context, flight <-chan struct{}) error {
	select {
	case <-flight:
		return nil
	case <-wait.Done():
		return supervisionWaitError(caller)
	}
}
func supervisionWaitError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrSupervisionBusy
}
