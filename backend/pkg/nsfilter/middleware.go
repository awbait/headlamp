package nsfilter

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/jmespath/go-jmespath"
	"github.com/kubernetes-sigs/headlamp/backend/pkg/auth"
	"github.com/kubernetes-sigs/headlamp/backend/pkg/logger"
)

// UsernameExtractor returns the username for the given request. The
// implementation typically inspects the OIDC cookie and decodes a JWT claim.
// An empty username with a nil error means "unauthenticated; do not filter".
type UsernameExtractor func(r *http.Request) (string, error)

// MiddlewareOptions configures Middleware.
type MiddlewareOptions struct {
	Resolver         *Resolver
	ExtractUsername  UsernameExtractor
	// Prober narrows the project-membership candidate set to namespaces the
	// user can actually access (per-namespace RBAC). When nil, the candidate
	// set is used verbatim, which mirrors Project membership but may include
	// namespaces where the user has no real role binding.
	Prober *Prober
	// Enabled toggles the whole middleware. When false, the wrapped handler is
	// invoked unchanged.
	Enabled bool
}

// Middleware returns an HTTP middleware that filters Kubernetes namespace
// listing/watch/get responses to the namespaces the authenticated user is
// allowed to see, according to Alaudas Project membership.
//
// It only acts on paths under /clusters/{name}/api/v1/namespaces. All other
// requests pass through untouched.
//
// Behaviour summary:
//   - GET /api/v1/namespaces            -> filter items[]
//   - GET /api/v1/namespaces?watch=1    -> filter event stream
//   - GET /api/v1/namespaces/{name}     -> 403 if name not allowed
//   - GET /api/v1/namespaces/{n}/...    -> 403 if n not allowed
//   - all other verbs (POST/PUT/...)    -> 403 (read-only filter; mutations
//                                         to namespace objects must be
//                                         enforced upstream by RBAC anyway,
//                                         we just refuse them here for clarity)
//
// On any internal error (resolver not ready, cannot determine username, etc.)
// the middleware fails closed: it returns 503 instead of leaking the unfiltered
// response.
func Middleware(opts MiddlewareOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if !opts.Enabled || opts.Resolver == nil || opts.ExtractUsername == nil {
			return next
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiPath := mux.Vars(r)["api"]
			kind, nsName := classify(apiPath)

			if kind == nsRequestNone {
				next.ServeHTTP(w, r)
				return
			}

			username, err := opts.ExtractUsername(r)
			if err != nil {
				logger.Log(logger.LevelError, nil, err, "nsfilter: extract username")
				writeStatus(w, http.StatusServiceUnavailable, "namespace authorization unavailable")

				return
			}

			if username == "" {
				// Unauthenticated request -- let the cluster auth layer reject
				// it; nothing for us to filter.
				next.ServeHTTP(w, r)
				return
			}

			allowed, err := opts.Resolver.AllowedNamespaces(username)
			if err != nil {
				logger.Log(logger.LevelError, map[string]string{"user": username}, err,
					"nsfilter: resolve allowed namespaces")
				writeStatus(w, http.StatusServiceUnavailable, "namespace authorization unavailable")

				return
			}

			// Narrow the project-level candidate set down to namespaces the
			// user actually has the probe permission in, mirroring what Alauda
			// UI shows. SSAR runs through the upstream Kubernetes API under
			// the user's bearer token, so the answer reflects real RBAC.
			if opts.Prober != nil && len(allowed) > 0 {
				idToken, terr := tokenFromCookie(r)
				if terr == nil && idToken != "" {
					narrowed, perr := opts.Prober.Narrow(r.Context(),
						MD5Hex(username), idToken, allowed)
					if perr != nil {
						logger.Log(logger.LevelError, map[string]string{"user": username}, perr,
							"nsfilter: SSAR narrow failed (failing closed)")
						writeStatus(w, http.StatusServiceUnavailable,
							"namespace authorization unavailable")

						return
					}

					allowed = narrowed
				}
			}

			// Strip Accept-Encoding so upstream returns plain JSON we can
			// parse without decompressing each variant. Headlamps client
			// will gzip-encode our response on the way out via the regular
			// compression middleware (if enabled).
			if kind == nsRequestList {
				r.Header.Del("Accept-Encoding")
			}

			switch kind {
			case nsRequestSingle:
				if _, ok := allowed[nsName]; !ok {
					writeStatus(w, http.StatusForbidden,
						"namespaces \""+nsName+"\" is forbidden by Headlamp policy")
					return
				}

				// Allowed: pass through.
				next.ServeHTTP(w, r)
			case nsRequestList:
				watch := isWatch(r)

				rec := newRecordingWriter(w, watch, allowed)
				next.ServeHTTP(rec, r)

				if !watch {
					rec.flushFiltered()
				}
			}
		})
	}
}

// nsRequest classification.
const (
	nsRequestNone   = 0
	nsRequestList   = 1 // namespaces or namespaces?watch=1
	nsRequestSingle = 2 // namespaces/<name> or namespaces/<name>/<sub>
)

// classify inspects the apiPath captured by gorilla/mux ({api:.*}) and returns
// the request kind and (for single requests) the target namespace name.
func classify(apiPath string) (int, string) {
	p := strings.TrimPrefix(apiPath, "/")
	if !strings.HasPrefix(p, "api/v1/namespaces") {
		return nsRequestNone, ""
	}

	rest := strings.TrimPrefix(p, "api/v1/namespaces")
	rest = strings.TrimPrefix(rest, "/")

	// Drop query string if it is part of the path (mux usually doesn't include
	// it but keep this defensive).
	if idx := strings.IndexByte(rest, '?'); idx >= 0 {
		rest = rest[:idx]
	}

	if rest == "" {
		return nsRequestList, ""
	}

	// /namespaces/<name>[/...]
	parts := strings.SplitN(rest, "/", 2)
	name := parts[0]

	if name == "" {
		return nsRequestList, ""
	}

	return nsRequestSingle, name
}

func isWatch(r *http.Request) bool {
	q := r.URL.Query()
	if v := q.Get("watch"); v != "" && v != "0" && v != "false" {
		return true
	}

	return false
}

func writeStatus(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	body := map[string]interface{}{
		"kind":       "Status",
		"apiVersion": "v1",
		"status":     "Failure",
		"message":    msg,
		"reason":     reasonFor(code),
		"code":       code,
	}
	_ = json.NewEncoder(w).Encode(body)
}

func reasonFor(code int) string {
	switch code {
	case http.StatusForbidden:
		return "Forbidden"
	case http.StatusServiceUnavailable:
		return "ServiceUnavailable"
	default:
		return "Failure"
	}
}

// recordingWriter buffers (or, in watch mode, streams) the upstream response
// and applies a namespace filter before forwarding bytes to the real
// ResponseWriter.
type recordingWriter struct {
	w       http.ResponseWriter
	allowed map[string]struct{}
	buf     bytes.Buffer
	header  http.Header
	status  int
	wrote   bool
	watch   bool
	stream  *streamFilter
}

func newRecordingWriter(w http.ResponseWriter, watch bool, allowed map[string]struct{}) *recordingWriter {
	rw := &recordingWriter{
		w:       w,
		allowed: allowed,
		header:  http.Header{},
		watch:   watch,
	}

	if watch {
		rw.stream = newStreamFilter(w, allowed)
	}

	return rw
}

func (rw *recordingWriter) Header() http.Header {
	return rw.header
}

func (rw *recordingWriter) WriteHeader(code int) {
	rw.status = code

	if rw.watch {
		rw.copyHeadersTo(rw.w.Header())
		rw.w.WriteHeader(code)
		rw.wrote = true
	}
}

func (rw *recordingWriter) Write(p []byte) (int, error) {
	if rw.status == 0 {
		rw.WriteHeader(http.StatusOK)
	}

	if rw.watch {
		return rw.stream.Write(p)
	}

	return rw.buf.Write(p)
}

func (rw *recordingWriter) Flush() {
	// In list mode we buffer everything until flushFiltered runs; flushing
	// the underlying writer here would trigger an implicit WriteHeader(200)
	// and cause a "superfluous response.WriteHeader" warning when we later
	// call WriteHeader explicitly.
	if !rw.watch {
		return
	}

	if f, ok := rw.w.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack lets WebSocket / Upgrade requests bubble through to the underlying
// ResponseWriter. Without this method httputil.ReverseProxy refuses to switch
// protocols (logs: "can't switch protocols using non-Hijacker ResponseWriter").
// We never wrap watch-stream upgrades with filtering anyway -- list/single
// classification handles plain JSON only -- so just delegate.
func (rw *recordingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := rw.w.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("nsfilter: ResponseWriter does not implement http.Hijacker")
	}

	return hj.Hijack()
}

func (rw *recordingWriter) copyHeadersTo(dst http.Header) {
	for k, vv := range rw.header {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// flushFiltered is invoked for non-watch list responses. It parses the buffered
// body as a Kubernetes List, filters items[] in place, and writes the result.
func (rw *recordingWriter) flushFiltered() {
	if rw.status == 0 {
		rw.status = http.StatusOK
	}

	// On non-2xx upstream responses just forward verbatim -- the user must see
	// the original error.
	if rw.status < 200 || rw.status >= 300 {
		rw.copyHeadersTo(rw.w.Header())
		rw.w.WriteHeader(rw.status)
		_, _ = rw.w.Write(rw.buf.Bytes())

		return
	}

	body := rw.buf.Bytes()

	// Some upstreams (e.g. erebus) ignore Accept-Encoding stripping and still
	// gzip the response. Decode transparently so the JSON parser sees plain
	// bytes; we re-emit uncompressed below.
	if strings.EqualFold(rw.header.Get("Content-Encoding"), "gzip") {
		decoded, derr := gunzip(body)
		if derr != nil {
			logger.Log(logger.LevelError, nil, derr, "nsfilter: gunzip upstream body, refusing")
			writeStatus(rw.w, http.StatusServiceUnavailable, "namespace authorization unavailable")

			return
		}

		body = decoded
	}

	filtered, err := filterListBody(body, rw.allowed)
	if err != nil {
		// Couldnt parse upstream payload: fail closed rather than leak.
		logger.Log(logger.LevelError, nil, err, "nsfilter: parse list body, refusing")
		writeStatus(rw.w, http.StatusServiceUnavailable, "namespace authorization unavailable")

		return
	}

	hdr := rw.w.Header()
	rw.copyHeadersTo(hdr)
	// Content-Length is no longer accurate after filtering; let the runtime
	// recompute or use chunked encoding. We also drop the Content-Encoding
	// because we always emit plain JSON.
	hdr.Del("Content-Length")
	hdr.Del("Content-Encoding")
	hdr.Set("Content-Type", "application/json")
	rw.w.WriteHeader(rw.status)
	_, _ = rw.w.Write(filtered)
}

func gunzip(b []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	return io.ReadAll(zr)
}

// filterListBody parses a Kubernetes NamespaceList JSON, filters items[] by
// allowed names, and returns the re-encoded body.
func filterListBody(body []byte, allowed map[string]struct{}) ([]byte, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}

	itemsRaw, ok := doc["items"]
	if !ok {
		// Not a List shape; return as is.
		return body, nil
	}

	var items []json.RawMessage
	if err := json.Unmarshal(itemsRaw, &items); err != nil {
		return nil, err
	}

	kept := make([]json.RawMessage, 0, len(items))

	for _, it := range items {
		name := extractName(it)
		if _, ok := allowed[name]; ok {
			kept = append(kept, it)
		}
	}

	keptRaw, err := json.Marshal(kept)
	if err != nil {
		return nil, err
	}

	doc["items"] = keptRaw

	return json.Marshal(doc)
}

func extractName(item json.RawMessage) string {
	var meta struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(item, &meta); err != nil {
		return ""
	}

	return meta.Metadata.Name
}

// streamFilter handles ?watch=1 chunked streams. Each line is a JSON
// envelope {"type":"...","object":{"kind":"Namespace","metadata":{"name":...}}}.
// We pass through events whose object name is in the allow-list, and drop
// the rest.
type streamFilter struct {
	w       http.ResponseWriter
	allowed map[string]struct{}
	rd      *io.PipeReader
	wr      *io.PipeWriter
	done    chan struct{}
}

func newStreamFilter(w http.ResponseWriter, allowed map[string]struct{}) *streamFilter {
	pr, pw := io.Pipe()
	s := &streamFilter{
		w:       w,
		allowed: allowed,
		rd:      pr,
		wr:      pw,
		done:    make(chan struct{}),
	}

	go s.loop()

	return s
}

func (s *streamFilter) Write(p []byte) (int, error) {
	return s.wr.Write(p)
}

func (s *streamFilter) loop() {
	defer close(s.done)

	flusher, _ := s.w.(http.Flusher)
	scanner := bufio.NewScanner(s.rd)
	// Default scanner buffer is too small for big watch events.
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		if !s.allowEvent(line) {
			continue
		}

		_, _ = s.w.Write(line)
		_, _ = s.w.Write([]byte("\n"))

		if flusher != nil {
			flusher.Flush()
		}
	}
}

func (s *streamFilter) allowEvent(line []byte) bool {
	var ev struct {
		Object struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"object"`
	}
	if err := json.Unmarshal(line, &ev); err != nil {
		return false
	}

	_, ok := s.allowed[ev.Object.Metadata.Name]

	return ok
}

// JWTUsernameExtractor builds a UsernameExtractor that decodes the OIDC
// cookie set by Headlamp and returns the configured username claim.
//
// usernamePaths is a comma-separated list of JMESPath expressions; the first
// non-empty match wins. Pass config.DefaultMeUsernamePath for stock behaviour.
func JWTUsernameExtractor(usernamePaths string) UsernameExtractor {
	return func(r *http.Request) (string, error) {
		clusterName := mux.Vars(r)["clusterName"]
		if clusterName == "" {
			return "", nil
		}

		token, err := auth.GetTokenFromCookie(r, clusterName)
		if err != nil || token == "" {
			return "", nil //nolint:nilerr // missing cookie -> not our scope
		}

		claims, status, msg := authParseClaims(token)
		if status != 0 {
			return "", errors.New(msg)
		}

		return usernameFromClaims(claims, usernamePaths), nil
	}
}

// authParseClaims decodes the JWT payload (middle base64url segment) without
// signature verification. Verification is performed elsewhere in the auth flow.
func authParseClaims(token string) (map[string]interface{}, int, string) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 || parts[1] == "" {
		return nil, http.StatusUnauthorized, "invalid token"
	}

	claims, err := auth.DecodeBase64JSON(parts[1])
	if err != nil {
		return nil, http.StatusUnauthorized, "invalid token claims"
	}

	return claims, 0, ""
}

// usernameFromClaims walks comma-separated JMESPath expressions and returns
// the first one resolving to a non-empty string.
func usernameFromClaims(claims map[string]interface{}, paths string) string {
	for _, raw := range strings.Split(paths, ",") {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}

		expr, err := jmespath.Compile(p)
		if err != nil {
			continue
		}

		res, err := expr.Search(claims)
		if err != nil || res == nil {
			continue
		}

		if s, ok := res.(string); ok && s != "" {
			return s
		}
	}

	return ""
}

// tokenFromCookie reads the OIDC bearer token from the per-cluster auth cookie
// without raising an error when missing. It is used by the nsfilter middleware
// to pass the user identity through to SelfSubjectAccessReview probes.
func tokenFromCookie(r *http.Request) (string, error) {
	clusterName := mux.Vars(r)["clusterName"]
	if clusterName == "" {
		return "", nil
	}

	tok, err := auth.GetTokenFromCookie(r, clusterName)
	if err != nil {
		return "", err
	}

	return tok, nil
}