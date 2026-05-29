package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

const (
	defaultSmartQuotaRefreshInterval = 10 * time.Minute
	defaultSmartResetMonitorInterval = time.Minute
	defaultSmartProbeCooldown        = 5 * time.Minute
	defaultSmartMaxConcurrentProbes  = 3
	smartResetMonitorJitterMax       = 30 * time.Second
	smartWeeklyProbeDriftMax         = 3 * time.Minute
	smartWeeklyRollingTolerance      = 30 * time.Second
	smartWeeklyWindow                = 7 * 24 * time.Hour
	claudeUsageURL                   = "https://api.anthropic.com/api/oauth/usage"
	codexUsageURL                    = "https://chatgpt.com/backend-api/wham/usage"
)

type smartRoutingMonitorConfig struct {
	QuotaRefreshInterval time.Duration
	ResetMonitorInterval time.Duration
	ProbeCooldown        time.Duration
	MaxConcurrentProbes  int
}

type smartRoutingMonitor struct {
	manager *Manager
}

type smartRoutingProbeResult struct {
	AuthID   string `json:"authId"`
	Index    string `json:"authIndex"`
	Provider string `json:"provider"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
}

func newSmartRoutingMonitor(manager *Manager) *smartRoutingMonitor {
	return &smartRoutingMonitor{manager: manager}
}

func smartRoutingMonitorConfigFromConfig(cfg *internalconfig.Config) smartRoutingMonitorConfig {
	routing := internalconfig.RoutingConfig{}
	if cfg != nil {
		routing = cfg.Routing
	}
	return smartRoutingMonitorConfig{
		QuotaRefreshInterval: parseDurationDefault(routing.SmartQuotaRefreshInterval, defaultSmartQuotaRefreshInterval),
		ResetMonitorInterval: parseDurationDefault(routing.SmartResetMonitorInterval, defaultSmartResetMonitorInterval),
		ProbeCooldown:        parseDurationDefault(routing.SmartProbeCooldown, defaultSmartProbeCooldown),
		MaxConcurrentProbes:  positiveIntDefault(routing.SmartMaxConcurrentProbes, defaultSmartMaxConcurrentProbes),
	}
}

func parseDurationDefault(raw string, fallback time.Duration) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func positiveIntDefault(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func (m *smartRoutingMonitor) run(ctx context.Context) {
	if m == nil || m.manager == nil {
		return
	}
	m.tick(ctx)
	cfg := smartRoutingMonitorConfigFromConfig(m.manager.configSnapshot())
	for {
		timer := time.NewTimer(smartRoutingMonitorIntervalWithOffset(cfg.ResetMonitorInterval))
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return
		case <-timer.C:
			m.tick(ctx)
			cfg = smartRoutingMonitorConfigFromConfig(m.manager.configSnapshot())
		}
	}
}

func smartRoutingMonitorIntervalWithOffset(base time.Duration) time.Duration {
	if base <= 0 {
		base = defaultSmartResetMonitorInterval
	}
	maxOffset := base / 10
	if maxOffset > smartResetMonitorJitterMax {
		maxOffset = smartResetMonitorJitterMax
	}
	if maxOffset <= 0 {
		return base
	}
	offset := time.Duration(rand.Int64N(int64(maxOffset))) + time.Nanosecond
	return base + offset
}

func (m *smartRoutingMonitor) tick(ctx context.Context) {
	manager := m.manager
	if manager == nil {
		return
	}
	selector := manager.smartRoutingSelector()
	if selector == nil {
		return
	}
	cfg := smartRoutingMonitorConfigFromConfig(manager.configSnapshot())
	auths := manager.snapshotAuths()
	now := time.Now()
	sem := make(chan struct{}, cfg.MaxConcurrentProbes)
	var wg sync.WaitGroup
	for _, auth := range auths {
		auth := auth
		if !smartRoutingMonitorEligible(auth) {
			continue
		}
		quota, ok := selector.Quota(auth.ID)
		stale := !ok || quota.LastQuotaRefreshAt.IsZero() || now.Sub(quota.LastQuotaRefreshAt) >= cfg.QuotaRefreshInterval
		dueProbe := ok && smartRoutingWeeklyProbeDue(quota, now, cfg)
		if !stale && !dueProbe {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			if stale {
				refreshed, refreshedOK := m.refreshQuota(ctx, selector, auth, quota, ok, now)
				if refreshedOK {
					quota = refreshed
					ok = true
				}
				if ok && smartRoutingWeeklyProbeDue(quota, now, cfg) {
					dueProbe = true
				}
			}
			if dueProbe && ok {
				_ = m.probeAndRefresh(ctx, selector, auth, true)
			}
		}()
	}
	wg.Wait()
}

func smartRoutingMonitorEligible(auth *Auth) bool {
	return auth != nil &&
		isSmartRoutingProvider(auth.Provider) &&
		!auth.Disabled &&
		auth.Status != StatusDisabled &&
		!auth.Unavailable
}

// ProbeSmartRouting sends a manual pinned probe to all currently available
// Claude/Codex auths. It is intended for user-triggered 5 hour window probes
// and does not require smart-routing to be the active selection strategy.
func (m *Manager) ProbeSmartRouting(ctx context.Context) map[string]any {
	selector := m.smartRoutingSelector()
	routingEnabled := selector != nil
	if selector == nil {
		selector = NewSmartRoutingSelector()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	monitor := newSmartRoutingMonitor(m)
	cfg := smartRoutingMonitorConfigFromConfig(m.configSnapshot())
	results := monitor.probeAll(ctx, selector, cfg)
	counts := map[string]int{"success": 0, "skipped": 0, "error": 0}
	for _, result := range results {
		counts[result.Status]++
	}
	return map[string]any{
		"enabled":        true,
		"routingEnabled": routingEnabled,
		"counts":         counts,
		"results":        results,
	}
}

func (m *smartRoutingMonitor) probeAll(ctx context.Context, selector *SmartRoutingSelector, cfg smartRoutingMonitorConfig) []smartRoutingProbeResult {
	if m == nil || m.manager == nil || selector == nil {
		return nil
	}
	auths := m.manager.snapshotAuths()
	now := time.Now()
	sem := make(chan struct{}, cfg.MaxConcurrentProbes)
	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make([]smartRoutingProbeResult, 0, len(auths))
	for _, auth := range auths {
		auth := auth
		if !smartRoutingMonitorEligible(auth) {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := smartRoutingProbeResult{
				AuthID:   auth.ID,
				Index:    auth.Index,
				Provider: auth.Provider,
				Status:   "success",
			}
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				result.Status = "error"
				result.Error = ctx.Err().Error()
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
				return
			}
			if quota, ok := selector.Quota(auth.ID); ok && smartRoutingProbeCoolingDown(quota, now, cfg) {
				result.Status = "skipped"
				result.Error = "probe cooldown active"
			} else if err := m.probeAndRefresh(ctx, selector, auth, false); err != nil {
				result.Status = "error"
				result.Error = err.Error()
			}
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool {
		if results[i].Provider != results[j].Provider {
			return results[i].Provider < results[j].Provider
		}
		if results[i].Index != results[j].Index {
			return results[i].Index < results[j].Index
		}
		return results[i].AuthID < results[j].AuthID
	})
	return results
}

func smartRoutingWeeklyProbeDue(quota SmartRoutingQuotaState, now time.Time, cfg smartRoutingMonitorConfig) bool {
	if smartRoutingProbeCoolingDown(quota, now, cfg) {
		return false
	}
	if quota.WeeklyProbeDueAt.IsZero() {
		return false
	}
	return !quota.WeeklyProbeDueAt.After(now)
}

func smartRoutingProbeCoolingDown(quota SmartRoutingQuotaState, now time.Time, cfg smartRoutingMonitorConfig) bool {
	return !quota.LastProbeAt.IsZero() && now.Sub(quota.LastProbeAt) < cfg.ProbeCooldown
}

func smartRoutingWeeklyProbeDueAt(previous SmartRoutingQuotaState, nextResetAt, now time.Time, hasPrevious bool) time.Time {
	if nextResetAt.IsZero() {
		return time.Time{}
	}
	if hasPrevious {
		if !previous.LastWeeklyProbeFor.IsZero() && previous.LastWeeklyProbeFor.Equal(nextResetAt) {
			return time.Time{}
		}
		if !previous.WeeklyProbeDueAt.IsZero() && previous.WeeklyResetAt.Equal(nextResetAt) {
			return previous.WeeklyProbeDueAt
		}
	}
	if smartRoutingWeeklyResetLooksRolling(nextResetAt, now) {
		return now
	}
	return nextResetAt.Add(smartRoutingWeeklyProbeDrift())
}

func smartRoutingWeeklyResetLooksRolling(resetAt, now time.Time) bool {
	if resetAt.IsZero() {
		return false
	}
	delta := resetAt.Sub(now)
	if delta < 0 {
		return false
	}
	diff := delta - smartWeeklyWindow
	if diff < 0 {
		diff = -diff
	}
	return diff <= smartWeeklyRollingTolerance
}

func smartRoutingWeeklyProbeDrift() time.Duration {
	return time.Duration(rand.Int64N(int64(smartWeeklyProbeDriftMax) + 1))
}

func (m *smartRoutingMonitor) refreshQuota(ctx context.Context, selector *SmartRoutingSelector, auth *Auth, previous SmartRoutingQuotaState, hasPrevious bool, now time.Time) (SmartRoutingQuotaState, bool) {
	quota, err := m.fetchQuota(ctx, auth)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			"component": "smart-routing",
			"auth_id":   auth.ID,
			"provider":  auth.Provider,
		}).Debug("quota refresh failed")
		return previous, false
	}
	if hasPrevious {
		quota.LastProbeAt = previous.LastProbeAt
		quota.LastProbeStatus = previous.LastProbeStatus
		quota.LastProbeError = previous.LastProbeError
		quota.LastWeeklyProbeAt = previous.LastWeeklyProbeAt
		quota.LastWeeklyProbeFor = previous.LastWeeklyProbeFor
	}
	quota.WeeklyProbeDueAt = smartRoutingWeeklyProbeDueAt(previous, quota.WeeklyResetAt, now, hasPrevious)
	selector.SetQuota(auth.ID, quota)
	return quota, true
}

func (m *smartRoutingMonitor) probeAndRefresh(ctx context.Context, selector *SmartRoutingSelector, auth *Auth, markWeekly bool) error {
	quota, ok := selector.Quota(auth.ID)
	if !ok {
		quota = SmartRoutingQuotaState{AuthID: auth.ID, AuthIndex: auth.Index, Provider: auth.Provider}
	}
	quota.LastProbeAt = time.Now()
	if err := m.sendProbe(ctx, auth); err != nil {
		quota.LastProbeStatus = "error"
		quota.LastProbeError = err.Error()
		selector.SetQuota(auth.ID, quota)
		log.WithError(err).WithFields(log.Fields{
			"component": "smart-routing",
			"auth_id":   auth.ID,
			"provider":  auth.Provider,
		}).Warn("quota reset probe failed")
		return err
	}
	quota.LastProbeStatus = "success"
	quota.LastProbeError = ""
	if markWeekly {
		quota.LastWeeklyProbeAt = quota.LastProbeAt
		quota.LastWeeklyProbeFor = quota.WeeklyResetAt
		quota.WeeklyProbeDueAt = time.Time{}
	}
	selector.SetQuota(auth.ID, quota)
	_, _ = m.refreshQuota(ctx, selector, auth, quota, true, time.Now())
	return nil
}

func (m *smartRoutingMonitor) fetchQuota(ctx context.Context, auth *Auth) (SmartRoutingQuotaState, error) {
	if auth == nil {
		return SmartRoutingQuotaState{}, fmt.Errorf("auth is nil")
	}
	var target string
	switch strings.ToLower(strings.TrimSpace(auth.Provider)) {
	case "claude":
		target = claudeUsageURL
	case "codex":
		target = codexUsageURL
	default:
		return SmartRoutingQuotaState{}, fmt.Errorf("unsupported smart-routing provider %q", auth.Provider)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return SmartRoutingQuotaState{}, err
	}
	resp, err := m.manager.HttpRequest(ctx, auth, req)
	if err != nil {
		return SmartRoutingQuotaState{}, err
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()
	if resp == nil {
		return SmartRoutingQuotaState{}, fmt.Errorf("quota response is nil")
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return SmartRoutingQuotaState{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return SmartRoutingQuotaState{}, fmt.Errorf("quota refresh status %d", resp.StatusCode)
	}
	quota := parseSmartRoutingQuota(auth, body, time.Now())
	return quota, nil
}

func parseSmartRoutingQuota(auth *Auth, body []byte, now time.Time) SmartRoutingQuotaState {
	quota := SmartRoutingQuotaState{
		LastQuotaRefreshAt: now,
	}
	if auth != nil {
		quota.AuthID = auth.ID
		quota.AuthIndex = auth.Index
		quota.Provider = strings.ToLower(strings.TrimSpace(auth.Provider))
	}
	switch quota.Provider {
	case "claude":
		fillClaudeSmartRoutingQuota(&quota, body, now)
	case "codex":
		fillCodexSmartRoutingQuota(&quota, body, now)
	}
	return quota
}

func fillClaudeSmartRoutingQuota(quota *SmartRoutingQuotaState, body []byte, now time.Time) {
	fiveHour := gjson.GetBytes(body, "five_hour")
	if fiveHour.Exists() {
		quota.FiveHourRemaining = remainingFromUtilization(fiveHour.Get("utilization"))
		quota.FiveHourResetAt = parseRFC3339Time(fiveHour.Get("resets_at").String())
	}
	weeklyKeys := []string{"seven_day", "seven_day_oauth_apps", "seven_day_opus", "seven_day_sonnet", "seven_day_cowork", "iguana_necktie"}
	for _, key := range weeklyKeys {
		window := gjson.GetBytes(body, key)
		if !window.Exists() {
			continue
		}
		remaining := remainingFromUtilization(window.Get("utilization"))
		if remaining != nil && (quota.WeeklyRemaining == nil || *remaining < *quota.WeeklyRemaining) {
			quota.WeeklyRemaining = remaining
		}
		resetAt := parseRFC3339Time(window.Get("resets_at").String())
		if !resetAt.IsZero() && (quota.WeeklyResetAt.IsZero() || resetAt.Before(quota.WeeklyResetAt)) {
			quota.WeeklyResetAt = resetAt
		}
	}
	_ = now
}

func fillCodexSmartRoutingQuota(quota *SmartRoutingQuotaState, body []byte, now time.Time) {
	if rateLimit := gjson.GetBytes(body, "rate_limit"); rateLimit.Exists() {
		fillCodexRateLimitWindow(quota, rateLimit.Get("primary_window"), true, now)
		fillCodexRateLimitWindow(quota, rateLimit.Get("secondary_window"), false, now)
	}
}

func fillCodexRateLimitWindow(quota *SmartRoutingQuotaState, window gjson.Result, fiveHour bool, now time.Time) {
	if !window.Exists() {
		return
	}
	remaining := remainingFromUsedPercent(window.Get("used_percent"))
	resetAt := codexResetAt(window, now)
	if fiveHour {
		quota.FiveHourRemaining = remaining
		quota.FiveHourResetAt = resetAt
		return
	}
	quota.WeeklyRemaining = remaining
	quota.WeeklyResetAt = resetAt
}

func remainingFromUtilization(value gjson.Result) *float64 {
	if !value.Exists() {
		return nil
	}
	remaining := 1 - value.Float()
	return clampRemaining(remaining)
}

func remainingFromUsedPercent(value gjson.Result) *float64 {
	if !value.Exists() {
		return nil
	}
	remaining := 1 - value.Float()/100
	return clampRemaining(remaining)
}

func clampRemaining(value float64) *float64 {
	if value < 0 {
		value = 0
	}
	if value > 1 {
		value = 1
	}
	return &value
}

func parseRFC3339Time(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err == nil {
		return parsed
	}
	parsed, err = time.Parse(time.RFC3339Nano, raw)
	if err == nil {
		return parsed
	}
	return time.Time{}
}

func codexResetAt(window gjson.Result, now time.Time) time.Time {
	if resetAt := window.Get("reset_at"); resetAt.Exists() {
		value := resetAt.Int()
		if value > 0 {
			if value > 1_000_000_000_000 {
				return time.UnixMilli(value)
			}
			return time.Unix(value, 0)
		}
	}
	if resetAfter := window.Get("reset_after_seconds"); resetAfter.Exists() {
		seconds := resetAfter.Int()
		if seconds > 0 {
			return now.Add(time.Duration(seconds) * time.Second)
		}
	}
	return time.Time{}
}

func (m *smartRoutingMonitor) sendProbe(ctx context.Context, auth *Auth) error {
	if auth == nil {
		return fmt.Errorf("auth is nil")
	}
	model := smartRoutingProbeModel(auth)
	payload, err := json.Marshal(map[string]any{
		"model":      model,
		"stream":     false,
		"max_tokens": 1,
		"messages": []map[string]string{{
			"role":    "user",
			"content": "test",
		}},
	})
	if err != nil {
		return err
	}
	opts := cliproxyexecutor.Options{
		Stream:          false,
		OriginalRequest: bytes.Clone(payload),
		SourceFormat:    sdktranslator.FromString("openai"),
		Metadata: map[string]any{
			cliproxyexecutor.PinnedAuthMetadataKey: auth.ID,
		},
	}
	req := cliproxyexecutor.Request{
		Model:   model,
		Payload: payload,
	}
	_, err = m.manager.Execute(ctx, []string{auth.Provider}, req, opts)
	return err
}

func smartRoutingProbeModel(auth *Auth) string {
	if auth != nil && auth.Attributes != nil {
		if model := strings.TrimSpace(auth.Attributes["test_model"]); model != "" {
			return model
		}
	}
	if auth != nil && strings.EqualFold(auth.Provider, "claude") {
		return "claude-sonnet-4-5"
	}
	return "gpt-5.5"
}

func smartRoutingStatus(selector *SmartRoutingSelector) map[string]any {
	if selector == nil {
		return map[string]any{"enabled": false}
	}
	selector.mu.Lock()
	defer selector.mu.Unlock()
	credentials := make([]map[string]any, 0, len(selector.quotas))
	for authID, quota := range selector.quotas {
		item := map[string]any{
			"authId":             authID,
			"authIndex":          quota.AuthIndex,
			"provider":           quota.Provider,
			"weeklyRemaining":    quota.WeeklyRemaining,
			"fiveHourRemaining":  quota.FiveHourRemaining,
			"lastQuotaRefreshAt": quota.LastQuotaRefreshAt,
			"lastProbeAt":        quota.LastProbeAt,
			"lastProbeStatus":    quota.LastProbeStatus,
			"lastProbeError":     quota.LastProbeError,
			"lastWeeklyProbeAt":  quota.LastWeeklyProbeAt,
		}
		if !quota.WeeklyResetAt.IsZero() {
			item["weeklyResetAt"] = quota.WeeklyResetAt
		}
		if !quota.FiveHourResetAt.IsZero() {
			item["fiveHourResetAt"] = quota.FiveHourResetAt
		}
		if !quota.WeeklyProbeDueAt.IsZero() {
			item["weeklyProbeDueAt"] = quota.WeeklyProbeDueAt
		}
		if !quota.LastWeeklyProbeFor.IsZero() {
			item["lastWeeklyProbeFor"] = quota.LastWeeklyProbeFor
		}
		credentials = append(credentials, item)
	}
	sort.Slice(credentials, func(i, j int) bool {
		leftProvider, _ := credentials[i]["provider"].(string)
		rightProvider, _ := credentials[j]["provider"].(string)
		if leftProvider != rightProvider {
			return leftProvider < rightProvider
		}
		leftIndex, _ := credentials[i]["authIndex"].(string)
		rightIndex, _ := credentials[j]["authIndex"].(string)
		if leftIndex != rightIndex {
			return leftIndex < rightIndex
		}
		leftID, _ := credentials[i]["authId"].(string)
		rightID, _ := credentials[j]["authId"].(string)
		return leftID < rightID
	})
	return map[string]any{
		"enabled":     true,
		"assignments": len(selector.assignments),
		"credentials": credentials,
	}
}
