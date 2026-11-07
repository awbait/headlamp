package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/kubernetes-sigs/headlamp/backend/pkg/cache"
	"github.com/kubernetes-sigs/headlamp/backend/pkg/config"
	"github.com/kubernetes-sigs/headlamp/backend/pkg/headlampconfig"
	"github.com/kubernetes-sigs/headlamp/backend/pkg/kubeconfig"
	"github.com/kubernetes-sigs/headlamp/backend/pkg/telemetry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/client-go/tools/clientcmd/api"
)

const (
	nsAccessCluster   = "main"
	nsAccessUserToken = "user-oidc"
	nsAccessListBody  = `{"kind":"NamespaceList","apiVersion":"v1","metadata":{"resourceVersion":"10"},` +
		`"items":[{"metadata":{"name":"visible"}},{"metadata":{"name":"hidden"}},{"metadata":{"name":"gone"}}]}`
)

// nsAccessUpstream is a fake kube-apiserver for the namespace access tests.
type nsAccessUpstream struct {
	mu          sync.Mutex
	getStatuses map[string]int
	probeAuth   []string
	// watchEvents are sent (base64 encoded) to namespace watch clients.
	watchEvents []string
	// ssarAllowed answers SelfSubjectAccessReviews per namespace; ssarStatus,
	// when set, replaces the answer with that HTTP status.
	ssarAllowed map[string]bool
	ssarStatus  int
	ssarAuth    []string
	ssarReviews []authorizationv1.ResourceAttributes
}

func (u *nsAccessUpstream) handler(t *testing.T) http.HandlerFunc {
	t.Helper()

	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == selfSubjectAccessReviewAPIPath:
			u.serveSSAR(t, w, r)
		case r.URL.Path == namespaceListAPIPath && r.URL.Query().Get("watch") != "":
			u.serveWatch(w, r)
		case r.URL.Path == namespaceListAPIPath:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(nsAccessListBody))
		case strings.HasPrefix(r.URL.Path, namespaceListAPIPath+"/"):
			name := strings.TrimPrefix(r.URL.Path, namespaceListAPIPath+"/")

			u.mu.Lock()
			u.probeAuth = append(u.probeAuth, r.Header.Get("Authorization"))
			status := u.getStatuses[name]
			u.mu.Unlock()

			w.WriteHeader(status)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func (u *nsAccessUpstream) serveSSAR(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()

	var review authorizationv1.SelfSubjectAccessReview
	if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&review)) ||
		!assert.NotNil(t, review.Spec.ResourceAttributes) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	attrs := *review.Spec.ResourceAttributes

	u.mu.Lock()
	u.ssarAuth = append(u.ssarAuth, r.Header.Get("Authorization"))
	u.ssarReviews = append(u.ssarReviews, attrs)
	status := u.ssarStatus
	review.Status.Allowed = u.ssarAllowed[attrs.Namespace]
	u.mu.Unlock()

	if status != 0 {
		w.WriteHeader(status)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(review)
}

func (u *nsAccessUpstream) serveWatch(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		Subprotocols: []string{"base64.binary.k8s.io"},
		CheckOrigin:  func(*http.Request) bool { return true },
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	defer func() { _ = ws.Close() }()

	for _, ev := range u.watchEvents {
		frame := base64.StdEncoding.EncodeToString([]byte(ev))
		if err := ws.WriteMessage(websocket.TextMessage, []byte(frame)); err != nil {
			return
		}
	}

	_ = ws.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
}

func newNamespaceAccessTestConfig(t *testing.T, upstreamURL string) *HeadlampConfig {
	t.Helper()

	store := kubeconfig.NewContextStore()
	require.NoError(t, store.AddContext(&kubeconfig.Context{
		Name: nsAccessCluster,
		Cluster: &api.Cluster{
			Server:                upstreamURL,
			InsecureSkipTLSVerify: true,
		},
		AuthInfo: &api.AuthInfo{},
	}))

	return &HeadlampConfig{
		HeadlampConfig: &headlampconfig.HeadlampConfig{
			HeadlampCFG: &headlampconfig.HeadlampCFG{
				KubeConfigStore: store,
			},
			Cache:            cache.New[interface{}](),
			TelemetryConfig:  GetDefaultTestTelemetryConfig(),
			TelemetryHandler: &telemetry.RequestHandler{},
		},
		namespaceFilter: newNamespaceFilter(),
	}
}

func nsAccessCookie() *http.Cookie {
	return &http.Cookie{
		Name:     "headlamp-auth-" + nsAccessCluster + ".0",
		Value:    nsAccessUserToken,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
}

func listedNamespaces(t *testing.T, body []byte) []string {
	t.Helper()

	var doc struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}

	require.NoError(t, json.Unmarshal(body, &doc))

	names := make([]string, 0, len(doc.Items))
	for _, item := range doc.Items {
		names = append(names, item.Metadata.Name)
	}

	return names
}

func TestRequireNamespaceGetFiltersList(t *testing.T) {
	upstream := &nsAccessUpstream{getStatuses: map[string]int{"visible": 200, "hidden": 403, "gone": 404}}
	server := httptest.NewTLSServer(upstream.handler(t))
	t.Cleanup(server.Close)

	c := newNamespaceAccessTestConfig(t, server.URL)
	router := mux.NewRouter()
	handleClusterAPI(c, router)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/clusters/"+nsAccessCluster+namespaceListAPIPath, nil)
	req.AddCookie(nsAccessCookie())

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, []string{"visible"}, listedNamespaces(t, rr.Body.Bytes()))
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	assert.Equal(t, rr.Body.Len(), func() int { l, _ := rr.Result().ContentLength, 0; return int(l) }())

	upstream.mu.Lock()
	defer upstream.mu.Unlock()

	require.Len(t, upstream.probeAuth, 3, "one GET probe per listed namespace")

	for _, auth := range upstream.probeAuth {
		assert.Equal(t, "Bearer "+nsAccessUserToken, auth, "probes must use the user's token")
	}
}

func TestRequireNamespaceGetPassesThroughWithoutUserToken(t *testing.T) {
	upstream := &nsAccessUpstream{getStatuses: map[string]int{"visible": 200}}
	server := httptest.NewTLSServer(upstream.handler(t))
	t.Cleanup(server.Close)

	c := newNamespaceAccessTestConfig(t, server.URL)
	router := mux.NewRouter()
	handleClusterAPI(c, router)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/clusters/"+nsAccessCluster+namespaceListAPIPath, nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, []string{"visible", "hidden", "gone"}, listedNamespaces(t, rr.Body.Bytes()))
	assert.Empty(t, upstream.probeAuth, "no probes without a user identity")
}

func TestRequireNamespaceGetFailsClosedOnProbeError(t *testing.T) {
	upstream := &nsAccessUpstream{getStatuses: map[string]int{"visible": 200, "hidden": 500, "gone": 404}}
	server := httptest.NewTLSServer(upstream.handler(t))
	t.Cleanup(server.Close)

	c := newNamespaceAccessTestConfig(t, server.URL)
	router := mux.NewRouter()
	handleClusterAPI(c, router)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/clusters/"+nsAccessCluster+namespaceListAPIPath, nil)
	req.AddCookie(nsAccessCookie())

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadGateway, rr.Code)
	assert.NotContains(t, rr.Body.String(), "hidden")
}

func TestRequireNamespaceGetLeavesOtherRequestsAlone(t *testing.T) {
	var upstreamRequests int

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests++

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"kind":"PodList","items":[{"metadata":{"name":"p","namespace":"hidden"}}]}`))
	}))
	t.Cleanup(server.Close)

	c := newNamespaceAccessTestConfig(t, server.URL)
	router := mux.NewRouter()
	handleClusterAPI(c, router)

	paths := []string{"/api/v1/pods", "/api/v1/namespaces/hidden", "/api/v1/namespaces/hidden/pods"}

	for _, path := range paths {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
			"/clusters/"+nsAccessCluster+path, nil)
		req.AddCookie(nsAccessCookie())

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code, path)
		assert.Contains(t, rr.Body.String(), "hidden", path)
	}

	assert.Equal(t, len(paths), upstreamRequests, "no extra access checks for non-list requests")
}

func TestRequireNamespaceGetFiltersWatch(t *testing.T) {
	upstream := &nsAccessUpstream{
		getStatuses: map[string]int{"visible": 200, "hidden": 403},
		watchEvents: []string{
			`{"type":"ADDED","object":{"metadata":{"name":"visible","resourceVersion":"11"}}}`,
			`{"type":"ADDED","object":{"metadata":{"name":"hidden","resourceVersion":"12"}}}`,
			`{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"13"}}}`,
		},
	}
	server := httptest.NewTLSServer(upstream.handler(t))
	t.Cleanup(server.Close)

	c := newNamespaceAccessTestConfig(t, server.URL)
	router := mux.NewRouter()
	handleClusterAPI(c, router)

	headlamp := httptest.NewServer(router)
	t.Cleanup(headlamp.Close)

	wsURL := "ws" + strings.TrimPrefix(headlamp.URL, "http") +
		"/clusters/" + nsAccessCluster + namespaceListAPIPath + "?watch=1&resourceVersion=10"

	dialer := websocket.Dialer{Subprotocols: []string{"base64.binary.k8s.io"}}
	headers := http.Header{"Cookie": {nsAccessCookie().String()}}

	ws, resp, err := dialer.Dial(wsURL, headers)
	require.NoError(t, err)

	defer func() { _ = resp.Body.Close() }()
	defer func() { _ = ws.Close() }()

	assert.Equal(t, "base64.binary.k8s.io", ws.Subprotocol())

	var received []string

	for {
		_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))

		_, frame, err := ws.ReadMessage()
		if err != nil {
			var closeErr *websocket.CloseError

			require.True(t, errors.As(err, &closeErr), "expected a clean close, got %v", err)

			break
		}

		decoded, err := base64.StdEncoding.DecodeString(string(frame))
		require.NoError(t, err)

		received = append(received, string(decoded))
	}

	require.Len(t, received, 2)
	assert.Contains(t, received[0], `"visible"`)
	assert.Contains(t, received[1], `"BOOKMARK"`)
}

func TestMultiplexerForwardNamespaceEvent(t *testing.T) {
	store := kubeconfig.NewContextStore()
	require.NoError(t, store.AddContext(&kubeconfig.Context{
		Name:    nsAccessCluster,
		Cluster: &api.Cluster{Server: "https://kube.invalid"},
	}))

	token := nsAccessUserToken
	visible := []byte(`{"type":"ADDED","object":{"metadata":{"name":"visible"}}}`)
	hidden := []byte(`{"type":"ADDED","object":{"metadata":{"name":"hidden"}}}`)

	m := NewMultiplexer(store, false)

	nsConn := &Connection{ClusterID: nsAccessCluster, Path: namespaceListAPIPath, Token: &token}

	assert.True(t, m.forwardNamespaceEvent(nsConn, hidden), "no filter installed: forward everything")

	m.SetNamespaceEventFilter(func(_ context.Context, kContext *kubeconfig.Context, gotToken string,
		event []byte,
	) (bool, error) {
		assert.Equal(t, nsAccessCluster, kContext.Name)
		assert.Equal(t, token, gotToken)

		if strings.Contains(string(event), "error") {
			return true, errors.New("probe failed")
		}

		return strings.Contains(string(event), "visible"), nil
	})

	assert.True(t, m.forwardNamespaceEvent(nsConn, visible))
	assert.False(t, m.forwardNamespaceEvent(nsConn, hidden))
	assert.False(t, m.forwardNamespaceEvent(nsConn, []byte(`{"type":"ADDED","object":{"metadata":{"name":"error"}}}`)),
		"filter errors drop the event")

	podConn := &Connection{ClusterID: nsAccessCluster, Path: "/api/v1/pods", Token: &token}
	assert.True(t, m.forwardNamespaceEvent(podConn, hidden), "other watches are not filtered")

	saConn := &Connection{
		ClusterID: nsAccessCluster, Path: namespaceListAPIPath, Token: &token, usesServiceAccountToken: true,
	}
	assert.True(t, m.forwardNamespaceEvent(saConn, hidden), "service account watches are not filtered")

	anonConn := &Connection{ClusterID: nsAccessCluster, Path: namespaceListAPIPath}
	assert.True(t, m.forwardNamespaceEvent(anonConn, hidden), "connections without a user token are not filtered")

	unknownConn := &Connection{ClusterID: "missing", Path: namespaceListAPIPath, Token: &token}
	assert.False(t, m.forwardNamespaceEvent(unknownConn, visible), "unknown contexts fail closed")
}

// newSSARNamespaceAccessTestConfig is newNamespaceAccessTestConfig with
// namespace-access-check=ssar for the given verb and resource.
func newSSARNamespaceAccessTestConfig(t *testing.T, upstreamURL, verb, resource string) *HeadlampConfig {
	t.Helper()

	c := newNamespaceAccessTestConfig(t, upstreamURL)
	c.namespaceProbe = newNamespaceProbeFactory(&config.Config{
		NamespaceAccessCheck:        config.NamespaceAccessCheckSSAR,
		NamespaceAccessSSARVerb:     verb,
		NamespaceAccessSSARResource: resource,
	})

	return c
}

func serveNamespaceList(t *testing.T, c *HeadlampConfig) *httptest.ResponseRecorder {
	t.Helper()

	router := mux.NewRouter()
	handleClusterAPI(c, router)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/clusters/"+nsAccessCluster+namespaceListAPIPath, nil)
	req.AddCookie(nsAccessCookie())

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	return rr
}

// TestNamespaceAccessSSARFiltersList checks that with
// namespace-access-check=ssar the listing is filtered by
// SelfSubjectAccessReviews for the configured verb and resource, sent with the
// user's token, and that a cluster-wide "get namespaces" (every GET answering
// 200) does not make hidden namespaces visible.
func TestNamespaceAccessSSARFiltersList(t *testing.T) {
	upstream := &nsAccessUpstream{
		getStatuses: map[string]int{"visible": 200, "hidden": 200, "gone": 200},
		ssarAllowed: map[string]bool{"visible": true},
	}
	server := httptest.NewTLSServer(upstream.handler(t))
	t.Cleanup(server.Close)

	rr := serveNamespaceList(t, newSSARNamespaceAccessTestConfig(t, server.URL, "list", "pods"))

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, []string{"visible"}, listedNamespaces(t, rr.Body.Bytes()))

	upstream.mu.Lock()
	defer upstream.mu.Unlock()

	assert.Empty(t, upstream.probeAuth, "no GET probes in ssar mode")
	require.Len(t, upstream.ssarReviews, 3, "one review per listed namespace")

	namespaces := make([]string, 0, len(upstream.ssarReviews))

	for i, attrs := range upstream.ssarReviews {
		assert.Equal(t, "Bearer "+nsAccessUserToken, upstream.ssarAuth[i], "reviews must use the user's token")
		assert.Equal(t, "list", attrs.Verb)
		assert.Equal(t, "pods", attrs.Resource)
		assert.Empty(t, attrs.Group)

		namespaces = append(namespaces, attrs.Namespace)
	}

	assert.ElementsMatch(t, []string{"visible", "hidden", "gone"}, namespaces)
}

// TestNamespaceAccessSSARFailsClosed checks that a review that cannot be
// completed (e.g. the user may not create SelfSubjectAccessReviews, or the
// API server fails) never returns an unfiltered list.
func TestNamespaceAccessSSARFailsClosed(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			upstream := &nsAccessUpstream{
				ssarAllowed: map[string]bool{"visible": true, "hidden": true, "gone": true},
				ssarStatus:  status,
			}
			server := httptest.NewTLSServer(upstream.handler(t))
			t.Cleanup(server.Close)

			rr := serveNamespaceList(t, newSSARNamespaceAccessTestConfig(t, server.URL, "list", "pods"))

			assert.Equal(t, http.StatusBadGateway, rr.Code)
			assert.NotContains(t, rr.Body.String(), "hidden")
		})
	}
}

// TestNewNamespaceProbeFactoryDefaultsToGet checks that GET probes stay the
// default.
func TestNewNamespaceProbeFactoryDefaultsToGet(t *testing.T) {
	upstream := &nsAccessUpstream{
		getStatuses: map[string]int{"visible": 200, "hidden": 403, "gone": 404},
		ssarAllowed: map[string]bool{"visible": true, "hidden": true, "gone": true},
	}
	server := httptest.NewTLSServer(upstream.handler(t))
	t.Cleanup(server.Close)

	c := newNamespaceAccessTestConfig(t, server.URL)
	c.namespaceProbe = newNamespaceProbeFactory(&config.Config{NamespaceAccessCheck: config.NamespaceAccessCheckGet})

	rr := serveNamespaceList(t, c)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Equal(t, []string{"visible"}, listedNamespaces(t, rr.Body.Bytes()))

	upstream.mu.Lock()
	defer upstream.mu.Unlock()

	assert.Len(t, upstream.probeAuth, 3)
	assert.Empty(t, upstream.ssarReviews, "no reviews in get mode")
}
