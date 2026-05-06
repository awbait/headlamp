package nsfilter

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kubernetes-sigs/headlamp/backend/pkg/logger"
	"golang.org/x/sync/semaphore"
)

// Prober narrows a candidate namespace set to those where the user actually
// has the configured probe permission (default: get pods). It calls
// SelfSubjectAccessReview against the configured upstream Kubernetes API
// (typically erebus) under the user's bearer token, so the answer reflects
// the real RBAC state -- including per-namespace RoleBindings that the
// project-level ProjectMember check cannot see.
type Prober struct {
	upstream    string // base URL, e.g. https://acp.../kubernetes/global
	httpClient  *http.Client
	verb        string // default: get
	resource    string // default: pods
	apiGroup    string // empty for core
	concurrency int64
	cacheTTL    time.Duration

	mu    sync.RWMutex
	cache map[string]proberCacheEntry // key: userHash + "|" + sortedCandidates
}

type proberCacheEntry struct {
	allowed map[string]struct{}
	expires time.Time
}

// ProberConfig configures a Prober.
type ProberConfig struct {
	Upstream      string
	SkipTLSVerify bool
	Verb          string
	Resource      string
	APIGroup      string
	Concurrency   int64
	CacheTTL      time.Duration
}

// NewProber builds a probe client. upstream is the URL of the Kubernetes API
// proxy (e.g. erebus). When SkipTLSVerify is true, server certificate
// verification is disabled (useful in dev clusters with self-signed certs).
func NewProber(cfg ProberConfig) (*Prober, error) {
	if strings.TrimSpace(cfg.Upstream) == "" {
		return nil, errors.New("nsfilter: empty upstream URL")
	}

	if _, err := url.Parse(cfg.Upstream); err != nil {
		return nil, fmt.Errorf("nsfilter: parse upstream URL: %w", err)
	}

	verb := cfg.Verb
	if verb == "" {
		verb = "get"
	}

	resource := cfg.Resource
	if resource == "" {
		resource = "pods"
	}

	conc := cfg.Concurrency
	if conc <= 0 {
		conc = 8
	}

	ttl := cfg.CacheTTL
	if ttl <= 0 {
		ttl = 60 * time.Second
	}

	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: cfg.SkipTLSVerify}, //nolint:gosec
		ForceAttemptHTTP2:     false,                                              //nolint:gosec
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		ResponseHeaderTimeout: 10 * time.Second,
	}

	return &Prober{
		upstream:    strings.TrimRight(cfg.Upstream, "/"),
		httpClient:  &http.Client{Transport: tr, Timeout: 15 * time.Second},
		verb:        verb,
		resource:    resource,
		apiGroup:    cfg.APIGroup,
		concurrency: conc,
		cacheTTL:    ttl,
		cache:       map[string]proberCacheEntry{},
	}, nil
}

// Narrow returns the subset of candidates the user is allowed to access via
// the configured probe verb/resource. idToken must be a valid Bearer credential
// understood by the upstream proxy (typically the OIDC id_token from the
// per-cluster cookie).
func (p *Prober) Narrow(ctx context.Context, userHash, idToken string,
	candidates map[string]struct{}) (map[string]struct{}, error) {
	if len(candidates) == 0 {
		return map[string]struct{}{}, nil
	}

	cacheKey := buildCacheKey(userHash, candidates)

	if hit, ok := p.cacheGet(cacheKey); ok {
		return hit, nil
	}

	out := make(map[string]struct{}, len(candidates))

	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = semaphore.NewWeighted(p.concurrency)
	)

	for ns := range candidates {
		ns := ns

		if err := sem.Acquire(ctx, 1); err != nil {
			return nil, fmt.Errorf("nsfilter: acquire semaphore: %w", err)
		}

		wg.Add(1)

		go func() {
			defer wg.Done()
			defer sem.Release(1)

			ok, perr := p.canAccess(ctx, idToken, ns)
			if perr != nil {
				logger.Log(logger.LevelError, map[string]string{"namespace": ns}, perr,
					"nsfilter: SSAR probe failed (treating as denied)")
				return
			}

			if ok {
				mu.Lock()
				out[ns] = struct{}{}
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	p.cachePut(cacheKey, out)

	return out, nil
}

// canAccess sends a single SelfSubjectAccessReview to the upstream API.
func (p *Prober) canAccess(ctx context.Context, idToken, namespace string) (bool, error) {
	body := map[string]interface{}{
		"apiVersion": "authorization.k8s.io/v1",
		"kind":       "SelfSubjectAccessReview",
		"spec": map[string]interface{}{
			"resourceAttributes": map[string]interface{}{
				"namespace": namespace,
				"verb":      p.verb,
				"group":     p.apiGroup,
				"resource":  p.resource,
			},
		},
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.upstream+"/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
		bytes.NewReader(payload))
	if err != nil {
		return false, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+idToken)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Errorf("upstream status %d", resp.StatusCode)
	}

	var ssar struct {
		Status struct {
			Allowed bool `json:"allowed"`
			Denied  bool `json:"denied"`
		} `json:"status"`
	}
	if derr := json.NewDecoder(resp.Body).Decode(&ssar); derr != nil {
		return false, derr
	}

	return ssar.Status.Allowed && !ssar.Status.Denied, nil
}

func (p *Prober) cacheGet(key string) (map[string]struct{}, bool) {
	p.mu.RLock()
	e, ok := p.cache[key]
	p.mu.RUnlock()

	if !ok || time.Now().After(e.expires) {
		return nil, false
	}

	out := make(map[string]struct{}, len(e.allowed))
	for k := range e.allowed {
		out[k] = struct{}{}
	}

	return out, true
}

func (p *Prober) cachePut(key string, allowed map[string]struct{}) {
	stored := make(map[string]struct{}, len(allowed))
	for k := range allowed {
		stored[k] = struct{}{}
	}

	p.mu.Lock()
	p.cache[key] = proberCacheEntry{allowed: stored, expires: time.Now().Add(p.cacheTTL)}
	p.mu.Unlock()
}

// buildCacheKey produces a stable key over (user, candidate-set). The key is
// resilient to map iteration order: we sort the namespace names.
func buildCacheKey(userHash string, candidates map[string]struct{}) string {
	names := make([]string, 0, len(candidates))
	for n := range candidates {
		names = append(names, n)
	}
	// Insert-sort: small N (typically <50).
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j-1] > names[j]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}

	return userHash + "|" + strings.Join(names, ",")
}