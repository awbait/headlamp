package nsfilter

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		path     string
		wantKind int
		wantName string
	}{
		{"api/v1/namespaces", nsRequestList, ""},
		{"/api/v1/namespaces", nsRequestList, ""},
		{"api/v1/namespaces/", nsRequestList, ""},
		{"api/v1/namespaces/foo", nsRequestSingle, "foo"},
		{"api/v1/namespaces/foo/pods", nsRequestSingle, "foo"},
		{"api/v1/pods", nsRequestNone, ""},
		{"apis/apps/v1/deployments", nsRequestNone, ""},
	}
	for _, tc := range cases {
		k, n := classify(tc.path)
		if k != tc.wantKind || n != tc.wantName {
			t.Errorf("classify(%q) = (%d, %q), want (%d, %q)",
				tc.path, k, n, tc.wantKind, tc.wantName)
		}
	}
}

func TestMD5Hex(t *testing.T) {
	got := MD5Hex("bolotovma-test")
	want := "aa268c16c82bd67b35b83a1d215dbe9b"
	if got != want {
		t.Errorf("MD5Hex(bolotovma-test) = %q, want %q", got, want)
	}
}

func TestFilterListBody(t *testing.T) {
	body := []byte(`{
	  "kind":"NamespaceList","apiVersion":"v1",
	  "metadata":{"resourceVersion":"1"},
	  "items":[
	    {"kind":"Namespace","metadata":{"name":"allowed-1"}},
	    {"kind":"Namespace","metadata":{"name":"forbidden"}},
	    {"kind":"Namespace","metadata":{"name":"allowed-2"}}
	  ]
	}`)
	allowed := map[string]struct{}{"allowed-1": {}, "allowed-2": {}}

	out, err := filterListBody(body, allowed)
	if err != nil {
		t.Fatalf("filterListBody: %v", err)
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	var items []map[string]interface{}
	if err := json.Unmarshal(doc["items"], &items); err != nil {
		t.Fatalf("unmarshal items: %v", err)
	}

	if len(items) != 2 {
		t.Fatalf("got %d items, want 2", len(items))
	}

	names := []string{
		items[0]["metadata"].(map[string]interface{})["name"].(string),
		items[1]["metadata"].(map[string]interface{})["name"].(string),
	}
	if !(names[0] == "allowed-1" && names[1] == "allowed-2") {
		t.Errorf("filtered names = %v", names)
	}
	// Top-level metadata must be preserved.
	if !bytes.Contains(out, []byte("resourceVersion")) {
		t.Errorf("top-level metadata lost")
	}
}

func TestMiddleware_Single_Forbidden(t *testing.T) {
	mw := Middleware(MiddlewareOptions{
		Enabled:  true,
		Resolver: stubResolver(map[string]struct{}{"allowed-1": {}}),
		ExtractUsername: func(r *http.Request) (string, error) {
			return "u", nil
		},
	})

	router := mux.NewRouter()
	router.PathPrefix("/clusters/{clusterName}/{api:.*}").Handler(
		mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("upstream must not be reached for forbidden ns")
			w.WriteHeader(http.StatusOK)
		})))

	req := httptest.NewRequest("GET", "/clusters/main/api/v1/namespaces/forbidden", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"reason":"Forbidden"`) {
		t.Errorf("body = %s", rr.Body.String())
	}
}

func TestMiddleware_List_Filters(t *testing.T) {
	mw := Middleware(MiddlewareOptions{
		Enabled:  true,
		Resolver: stubResolver(map[string]struct{}{"allowed-1": {}}),
		ExtractUsername: func(r *http.Request) (string, error) {
			return "u", nil
		},
	})

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"kind":"NamespaceList","apiVersion":"v1","metadata":{},"items":[
		  {"metadata":{"name":"allowed-1"}},{"metadata":{"name":"x"}}]}`))
	})

	router := mux.NewRouter()
	router.PathPrefix("/clusters/{clusterName}/{api:.*}").Handler(mw(upstream))

	req := httptest.NewRequest("GET", "/clusters/main/api/v1/namespaces", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "allowed-1") || strings.Contains(rr.Body.String(), `"name":"x"`) {
		t.Errorf("body not filtered: %s", rr.Body.String())
	}
}

// stubResolver implements just enough of *Resolver via a thin wrapper so the
// middleware tests don't require running informers.
type stubResolverImpl struct{ allowed map[string]struct{} }

func stubResolver(allowed map[string]struct{}) *Resolver {
	r := &Resolver{
		cfg:     Config{ProjectLabel: DefaultProjectLabel},
		started: true,
		stopCh:  make(chan struct{}),
	}
	r.testAllowed = allowed
	return r
}