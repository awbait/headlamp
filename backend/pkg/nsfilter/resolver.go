// Package nsfilter implements server-side namespace filtering based on Alauda
// Project membership. It maintains an in-memory index of user->namespaces
// mappings, kept in sync via Kubernetes informers, and exposes a middleware
// that filters /api/v1/namespaces responses for the authenticated user.
//
// Identity model:
//   ProjectMember (cluster-scoped CRD auth.alauda.io/v1) carries labels:
//     cpaas.io/user    = MD5(username)
//     cpaas.io/project = <project name>
//   Namespace (core/v1) carries label:
//     cpaas.io/project = <project name>
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// Defaults for the labels used by Alaudas RBAC model.
const (
	DefaultUserLabel    = "cpaas.io/user"
	DefaultProjectLabel = "cpaas.io/project"
	syncTimeout         = 60 * time.Second
)

// projectMemberGVR identifies the Alauda ProjectMember CRD.
var projectMemberGVR = schema.GroupVersionResource{
	Group:    "auth.alauda.io",
	Version:  "v1",
	Resource: "projectmembers",
}

// Config controls how the resolver indexes data.
type Config struct {
	UserLabel    string
	ProjectLabel string
}

// Resolver answers "which namespaces is <user> allowed to see?" using
// in-memory data populated by Kubernetes informers.
type Resolver struct {
	cfg Config

	pmFactory dynamicinformer.DynamicSharedInformerFactory
	nsFactory informers.SharedInformerFactory

	nsLister corev1listers.NamespaceLister

	mu      sync.RWMutex
	pmIndex map[string]map[string]struct{} // userHash -> set(project)

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

	if cfg.UserLabel == "" {
		cfg.UserLabel = DefaultUserLabel
	}

	if cfg.ProjectLabel == "" {
		cfg.ProjectLabel = DefaultProjectLabel
	}

	dynClient, err := dynamic.NewForConfig(rc)
	if err != nil {
		return nil, fmt.Errorf("nsfilter: dynamic client: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, fmt.Errorf("nsfilter: clientset: %w", err)
	}

	r := &Resolver{
		cfg:       cfg,
		pmFactory: dynamicinformer.NewDynamicSharedInformerFactory(dynClient, 10*time.Minute),
		nsFactory: informers.NewSharedInformerFactory(clientset, 10*time.Minute),
		pmIndex:   map[string]map[string]struct{}{},
		stopCh:    make(chan struct{}),
	}

	return r, nil
}

// Start launches both informers and waits for the initial sync.
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

	pmInf := r.pmFactory.ForResource(projectMemberGVR).Informer()
	if _, err := pmInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    r.handlePMAddOrUpdate,
		UpdateFunc: func(_, newObj interface{}) { r.handlePMAddOrUpdate(newObj) },
		DeleteFunc: r.handlePMDelete,
	}); err != nil {
		return fmt.Errorf("nsfilter: add pm handler: %w", err)
	}

	r.nsFactory.Start(r.stopCh)
	r.pmFactory.Start(r.stopCh)

	syncCtx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()

	if !cache.WaitForCacheSync(syncCtx.Done(), nsInf.Informer().HasSynced, pmInf.HasSynced) {
		return errors.New("nsfilter: timed out waiting for informer sync")
	}

	logger.Log(logger.LevelInfo, nil, nil, "nsfilter: informers synced")

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

// IsReady reports whether informers have completed their initial sync and
// the resolver is operating.
func (r *Resolver) IsReady() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.started
}

// AllowedNamespaces returns the set of namespace names visible to username.
// An empty (non-nil) map means "no namespaces" (zero memberships).
func (r *Resolver) AllowedNamespaces(username string) (map[string]struct{}, error) {
	if username == "" {
		return nil, errors.New("nsfilter: empty username")
	}

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

	hash := MD5Hex(username)

	r.mu.RLock()
	projectsForUser := r.pmIndex[hash]
	projectSet := make(map[string]struct{}, len(projectsForUser))
	for p := range projectsForUser {
		projectSet[p] = struct{}{}
	}
	r.mu.RUnlock()

	if len(projectSet) == 0 {
		return map[string]struct{}{}, nil
	}

	// Build a label requirement: cpaas.io/project exists.
	req, err := labels.NewRequirement(r.cfg.ProjectLabel, selection.Exists, nil)
	if err != nil {
		return nil, fmt.Errorf("nsfilter: build label requirement: %w", err)
	}

	sel := labels.NewSelector().Add(*req)

	all, err := r.nsLister.List(sel)
	if err != nil {
		return nil, fmt.Errorf("nsfilter: list namespaces: %w", err)
	}

	result := make(map[string]struct{}, 8)

	for _, ns := range all {
		proj := ns.Labels[r.cfg.ProjectLabel]
		if _, ok := projectSet[proj]; ok {
			result[ns.Name] = struct{}{}
		}
	}

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

// MD5Hex returns the lowercase hex MD5 digest of s. Used as the identity
// index expected by Alaudas ProjectMember labels.
func MD5Hex(s string) string {
	sum := md5.Sum([]byte(s)) //nolint:gosec
	return hex.EncodeToString(sum[:])
}

func (r *Resolver) handlePMAddOrUpdate(obj interface{}) {
	userHash, project, ok := r.extractPMLabels(obj)
	if !ok {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	set, exists := r.pmIndex[userHash]
	if !exists {
		set = map[string]struct{}{}
		r.pmIndex[userHash] = set
	}

	set[project] = struct{}{}
}

func (r *Resolver) handlePMDelete(obj interface{}) {
	if tomb, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = tomb.Obj
	}

	userHash, project, ok := r.extractPMLabels(obj)
	if !ok {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if set, exists := r.pmIndex[userHash]; exists {
		delete(set, project)
		if len(set) == 0 {
			delete(r.pmIndex, userHash)
		}
	}
}

func (r *Resolver) extractPMLabels(obj interface{}) (userHash, project string, ok bool) {
	meta, mok := obj.(metav1.Object)
	if !mok {
		return "", "", false
	}

	lbls := meta.GetLabels()
	if lbls == nil {
		return "", "", false
	}

	userHash = lbls[r.cfg.UserLabel]
	project = lbls[r.cfg.ProjectLabel]

	if userHash == "" || project == "" {
		return "", "", false
	}

	return userHash, project, true
}