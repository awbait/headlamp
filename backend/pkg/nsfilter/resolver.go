// Package nsfilter implements server-side namespace filtering. The candidate
// set of namespaces is built from the cluster (via an informer-backed lister)
// using a configurable label that marks "platform-managed" namespaces (Alauda
// uses cpaas.io/project). The candidate set is then narrowed per-user via
// SelfSubjectAccessReview against the upstream Kubernetes API, so the result
// reflects the user's real RBAC -- including group-only memberships.
//
// Identity model:
//   Namespace (core/v1) carries label cpaas.io/project=<project>. We do NOT
//   try to map user->namespaces ourselves; that is delegated to the apiserver
//   through SSAR (see Prober).
package nsfilter

import (
	"context"
	"crypto/md5" //nolint:gosec // identity index, not a security primitive.
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/kubernetes-sigs/headlamp/backend/pkg/logger"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// Default project label used by Alauda's RBAC model.
const (
	DefaultProjectLabel = "cpaas.io/project"
	syncTimeout         = 60 * time.Second
)

// Config controls how the resolver builds the candidate set.
type Config struct {
	// ProjectLabel is the label that, when present on a namespace, marks it
	// as a candidate for filtering. Namespaces without this label are
	// always excluded from the candidate set (so kube-system etc. never
	// leak into the user's view).
	ProjectLabel string
}

// Resolver builds the per-request candidate namespace set from the cluster's
// labelled namespaces. The actual user-level narrowing is performed by Prober.
type Resolver struct {
	cfg Config

	nsFactory informers.SharedInformerFactory
	nsLister  corev1listers.NamespaceLister

	mu      sync.RWMutex
	started bool
	stopCh  chan struct{}

	// testAllowed, if non-nil, short-circuits AllowedNamespaces. Used by
	// unit tests that exercise the middleware without informers.
	testAllowed map[string]struct{}
}

// NewResolver builds a resolver. It does not start informers; call Start.
func NewResolver(rc *rest.Config, cfg Config) (*Resolver, error) {
	if rc == nil {
		return nil, errors.New("nsfilter: nil rest.Config")
	}

	if cfg.ProjectLabel == "" {
		cfg.ProjectLabel = DefaultProjectLabel
	}

	clientset, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, fmt.Errorf("nsfilter: clientset: %w", err)
	}

	r := &Resolver{
		cfg:       cfg,
		nsFactory: informers.NewSharedInformerFactory(clientset, 10*time.Minute),
		stopCh:    make(chan struct{}),
	}

	return r, nil
}

// Start launches the namespace informer and waits for the initial sync.
func (r *Resolver) Start(ctx context.Context) error {
	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return nil
	}

	r.started = true
	r.mu.Unlock()

	nsInf := r.nsFactory.Core().V1().Namespaces()
	r.nsLister = nsInf.Lister()
	_ = nsInf.Informer()

	r.nsFactory.Start(r.stopCh)

	syncCtx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()

	if !cache.WaitForCacheSync(syncCtx.Done(), nsInf.Informer().HasSynced) {
		return errors.New("nsfilter: timed out waiting for informer sync")
	}

	logger.Log(logger.LevelInfo, nil, nil, "nsfilter: namespace informer synced")

	return nil
}

// Stop shuts down the informers.
func (r *Resolver) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.started {
		return
	}

	close(r.stopCh)
	r.started = false
}

// IsReady reports whether the namespace informer has completed its initial sync.
func (r *Resolver) IsReady() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.started
}

// AllowedNamespaces returns the candidate set: every namespace currently
// labelled with ProjectLabel. Per-user narrowing happens later in Prober.
//
// The username argument is accepted for API compatibility and logging only;
// the candidate set is identical for every caller. Returning the same set
// here is safe because:
//   - downstream Prober narrows it under the caller's bearer token via SSAR;
//   - middleware fails closed if Prober is missing or returns an error.
//
// An empty (non-nil) map means "no labelled namespaces in cluster yet".
func (r *Resolver) AllowedNamespaces(username string) (map[string]struct{}, error) {
	if !r.IsReady() {
		return nil, errors.New("nsfilter: resolver not ready")
	}

	if r.testAllowed != nil {
		out := make(map[string]struct{}, len(r.testAllowed))
		for k := range r.testAllowed {
			out[k] = struct{}{}
		}

		return out, nil
	}

	req, err := labels.NewRequirement(r.cfg.ProjectLabel, selection.Exists, nil)
	if err != nil {
		return nil, fmt.Errorf("nsfilter: build label requirement: %w", err)
	}

	sel := labels.NewSelector().Add(*req)

	all, err := r.nsLister.List(sel)
	if err != nil {
		return nil, fmt.Errorf("nsfilter: list namespaces: %w", err)
	}

	result := make(map[string]struct{}, len(all))
	for _, ns := range all {
		result[ns.Name] = struct{}{}
	}

	_ = username // accepted for API compat / future per-user pre-filters

	return result, nil
}

// IsAllowed is a convenience wrapper for single-namespace checks.
func (r *Resolver) IsAllowed(username, namespace string) (bool, error) {
	allowed, err := r.AllowedNamespaces(username)
	if err != nil {
		return false, err
	}

	_, ok := allowed[namespace]

	return ok, nil
}

// MD5Hex returns the lowercase hex MD5 digest of s. Kept exported because
// the SSAR Prober uses it as an opaque user-id-hash for cache keys.
func MD5Hex(s string) string {
	sum := md5.Sum([]byte(s)) //nolint:gosec
	return hex.EncodeToString(sum[:])
}
