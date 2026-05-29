package auth

import (
	"context"
	"hash/fnv"
	"math/rand/v2"
	"sort"
	"strings"
	"sync"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

const smartRoutingDefaultTTL = 5 * time.Hour

// SmartRoutingQuotaState is the quota snapshot used by smart-routing priority.
type SmartRoutingQuotaState struct {
	AuthID             string
	AuthIndex          string
	Provider           string
	WeeklyRemaining    *float64
	FiveHourRemaining  *float64
	WeeklyResetAt      time.Time
	FiveHourResetAt    time.Time
	WeeklyProbeDueAt   time.Time
	LastQuotaRefreshAt time.Time
	LastProbeAt        time.Time
	LastProbeStatus    string
	LastProbeError     string
	LastWeeklyProbeAt  time.Time
	LastWeeklyProbeFor time.Time
}

// SmartRoutingConfig configures the smart-routing selector.
type SmartRoutingConfig struct {
	TTL        time.Duration
	Fallback   Selector
	Now        func() time.Time
	TieBreaker func(*Auth) uint64
}

type smartRoutingAssignment struct {
	AuthID    string
	ExpiresAt time.Time
}

type smartRoutingCandidate struct {
	auth       *Auth
	quota      SmartRoutingQuotaState
	hasQuota   bool
	tieBreaker uint64
}

// SmartRoutingSelector selects Claude/Codex credentials by quota priority while
// keeping a sticky client identity to auth binding.
type SmartRoutingSelector struct {
	mu          sync.Mutex
	ttl         time.Duration
	fallback    Selector
	now         func() time.Time
	tieBreaker  func(*Auth) uint64
	quotas      map[string]SmartRoutingQuotaState
	assignments map[string]smartRoutingAssignment
	cursors     map[string]int
}

func NewSmartRoutingSelector() *SmartRoutingSelector {
	return NewSmartRoutingSelectorWithConfig(SmartRoutingConfig{})
}

func NewSmartRoutingSelectorWithConfig(cfg SmartRoutingConfig) *SmartRoutingSelector {
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = smartRoutingDefaultTTL
	}
	fallback := cfg.Fallback
	if fallback == nil {
		fallback = &FillFirstSelector{}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	tieBreaker := cfg.TieBreaker
	if tieBreaker == nil {
		tieBreaker = stableSmartRoutingTieBreaker
	}
	return &SmartRoutingSelector{
		ttl:         ttl,
		fallback:    fallback,
		now:         now,
		tieBreaker:  tieBreaker,
		quotas:      make(map[string]SmartRoutingQuotaState),
		assignments: make(map[string]smartRoutingAssignment),
		cursors:     make(map[string]int),
	}
}

func (s *SmartRoutingSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	now := s.currentTime()
	available, err := getAvailableAuths(auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	if !allSmartRoutingAuths(available) {
		return s.fallback.Pick(ctx, provider, model, opts, auths)
	}

	identity := smartRoutingIdentity(opts)
	priorityKey := smartRoutingPriorityKey(provider, model)

	s.mu.Lock()
	defer s.mu.Unlock()

	candidates := s.rankCandidatesLocked(available)
	if len(candidates) == 0 {
		return nil, &Error{Code: "auth_not_found", Message: "no auth available"}
	}

	if identity != "" {
		assignmentKey := priorityKey + "::" + identity
		if assigned, ok := s.assignments[assignmentKey]; ok {
			if assigned.ExpiresAt.IsZero() || assigned.ExpiresAt.After(now) {
				for _, candidate := range candidates {
					if candidate.auth != nil && candidate.auth.ID == assigned.AuthID {
						s.assignments[assignmentKey] = smartRoutingAssignment{
							AuthID:    assigned.AuthID,
							ExpiresAt: now.Add(s.ttl),
						}
						return candidate.auth, nil
					}
				}
			}
			delete(s.assignments, assignmentKey)
		}
	}

	index := s.cursors[priorityKey]
	if index < 0 {
		index = 0
	}
	picked := candidates[index%len(candidates)].auth
	s.cursors[priorityKey] = index + 1
	if identity != "" && picked != nil {
		s.assignments[priorityKey+"::"+identity] = smartRoutingAssignment{
			AuthID:    picked.ID,
			ExpiresAt: now.Add(s.ttl),
		}
	}
	return picked, nil
}

func (s *SmartRoutingSelector) SetQuota(authID string, quota SmartRoutingQuotaState) {
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return
	}
	quota.AuthID = authID
	s.mu.Lock()
	defer s.mu.Unlock()
	s.quotas[authID] = quota
}

func (s *SmartRoutingSelector) Quota(authID string) (SmartRoutingQuotaState, bool) {
	authID = strings.TrimSpace(authID)
	if authID == "" {
		return SmartRoutingQuotaState{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	quota, ok := s.quotas[authID]
	return quota, ok
}

func (s *SmartRoutingSelector) assignmentCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.assignments)
}

func (s *SmartRoutingSelector) currentTime() time.Time {
	if s == nil || s.now == nil {
		return time.Now()
	}
	return s.now()
}

func (s *SmartRoutingSelector) rankCandidatesLocked(auths []*Auth) []smartRoutingCandidate {
	candidates := make([]smartRoutingCandidate, 0, len(auths))
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		quota, ok := s.quotas[auth.ID]
		candidates = append(candidates, smartRoutingCandidate{
			auth:       auth,
			quota:      quota,
			hasQuota:   ok,
			tieBreaker: s.tieBreaker(auth),
		})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		left := candidates[i]
		right := candidates[j]
		if cmp := compareQuotaRemaining(left.quota.WeeklyRemaining, right.quota.WeeklyRemaining); cmp != 0 {
			return cmp > 0
		}
		if cmp := compareQuotaRemaining(left.quota.FiveHourRemaining, right.quota.FiveHourRemaining); cmp != 0 {
			return cmp > 0
		}
		if left.hasQuota != right.hasQuota {
			return left.hasQuota
		}
		if left.tieBreaker != right.tieBreaker {
			return left.tieBreaker < right.tieBreaker
		}
		leftID := ""
		rightID := ""
		if left.auth != nil {
			leftID = left.auth.ID
		}
		if right.auth != nil {
			rightID = right.auth.ID
		}
		return leftID < rightID
	})
	return candidates
}

func compareQuotaRemaining(left, right *float64) int {
	if left == nil && right == nil {
		return 0
	}
	if left == nil {
		return -1
	}
	if right == nil {
		return 1
	}
	if *left > *right {
		return 1
	}
	if *left < *right {
		return -1
	}
	return 0
}

func smartRoutingIdentity(opts cliproxyexecutor.Options) string {
	if opts.Metadata != nil {
		if raw, ok := opts.Metadata[cliproxyexecutor.SmartRoutingIdentityMetadataKey]; ok {
			if value := strings.TrimSpace(toString(raw)); value != "" {
				return "id:" + value
			}
		}
	}
	if id := ExtractSessionID(opts.Headers, opts.OriginalRequest, opts.Metadata); id != "" {
		return "session:" + id
	}
	if opts.Metadata != nil {
		if raw, ok := opts.Metadata[cliproxyexecutor.SmartRoutingClientIPMetadataKey]; ok {
			if value := strings.TrimSpace(toString(raw)); value != "" {
				return "ip:" + value
			}
		}
	}
	return ""
}

func toString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return ""
	}
}

func smartRoutingPriorityKey(provider, model string) string {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		provider = "mixed"
	}
	return provider + "::" + canonicalModelKey(model)
}

func allSmartRoutingAuths(auths []*Auth) bool {
	if len(auths) == 0 {
		return false
	}
	for _, auth := range auths {
		if auth == nil || !isSmartRoutingProvider(auth.Provider) {
			return false
		}
	}
	return true
}

func isSmartRoutingProvider(provider string) bool {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "claude", "codex":
		return true
	default:
		return false
	}
}

func stableSmartRoutingTieBreaker(auth *Auth) uint64 {
	seed := ""
	if auth != nil {
		seed = auth.ID
		if seed == "" {
			seed = auth.Index
		}
	}
	if seed == "" {
		return rand.Uint64()
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(seed))
	return h.Sum64()
}
