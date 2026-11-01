package dynv

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// MaxBody caps a response body (bytes).
const MaxBody = 32 << 20

var (
	clientInstanceOnce sync.Once
	clientInstance     string
)

// directClientInstance returns the one random identifier shared by all direct
// clients for this process's lifetime. It is generated only when needed.
func directClientInstance() string {
	clientInstanceOnce.Do(func() {
		var raw [16]byte
		if _, err := rand.Read(raw[:]); err != nil {
			panic("dynv: cannot generate client instance id: " + err.Error())
		}
		clientInstance = base64.RawURLEncoding.EncodeToString(raw[:])
	})
	return clientInstance
}

// HTTPError is a non-200/204 answer from the API or the agent (a 3xx
// included: redirects are never followed).
type HTTPError struct {
	Status  int
	Message string
}

func (e *HTTPError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("dynv: HTTP %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("dynv: HTTP %d", e.Status)
}

// CheckURL applies the §5 rules to a base URL: https only (http to loopback,
// or anywhere with allowInsecureHTTP), no credentials, query or fragment.
// It returns the URL without trailing slashes.
func CheckURL(raw string, allowInsecureHTTP bool) (string, error) {
	s := strings.TrimSpace(raw)
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.Opaque != "" {
		return "", errors.New("dynv: DYNV_URL is not a valid absolute URL")
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(s, "?#") {
		return "", errors.New("dynv: DYNV_URL must be a plain base URL (no credentials, query or fragment)")
	}
	ok := false
	switch strings.ToLower(u.Scheme) {
	case "https":
		ok = true
	case "http":
		ok = allowInsecureHTTP || isLoopback(u.Hostname())
	}
	if !ok {
		return "", errors.New("dynv: DYNV_URL must use https:// (http:// only to loopback or with DYNV_ALLOW_INSECURE_HTTP=1)")
	}
	return strings.TrimRight(s, "/"), nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// noRedirect makes a copy of c (or a default client) that never follows a
// redirect: the 3xx itself comes back and is treated as an error, so the
// Authorization header can't be carried to another host (§5).
func noRedirect(c *http.Client) *http.Client {
	var out http.Client
	if c != nil {
		out = *c
	}
	out.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &out
}

// getBody does one GET. It returns (nil, nil) for 204, the body for 200
// (at most MaxBody bytes), and an error otherwise. A non-empty instance is
// sent only by the direct API paths.
func getBody(ctx context.Context, c *http.Client, u, auth, instance string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", auth)
	if instance != "" {
		req.Header.Set("X-Dynv-Client-Instance", instance)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "dynv-go/1")
	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, MaxBody+1))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		e := &HTTPError{Status: res.StatusCode}
		switch {
		case res.StatusCode == http.StatusUnauthorized:
			e.Message = "token rejected (revoked or wrong)"
		case res.StatusCode >= 300 && res.StatusCode < 400:
			e.Message = "redirect refused"
		}
		return nil, e
	}
	if len(body) > MaxBody {
		return nil, errors.New("dynv: response too large")
	}
	return body, nil
}

// get is getBody plus strict JSON parsing; (nil, nil) for 204.
func get(ctx context.Context, c *http.Client, u, auth, instance string) (any, error) {
	body, err := getBody(ctx, c, u, auth, instance)
	if err != nil || body == nil {
		return nil, err
	}
	v, err := ParseJSON(body)
	if err != nil {
		return nil, errors.New("dynv: response is not JSON")
	}
	return v, nil
}

// WriteCache writes data atomically and durably (§9): a new file with an
// unpredictable name next to the target, created exclusively with mode
// 0600 (never following a planted symlink), fsync, rename, fsync the
// directory.
func WriteCache(path string, data []byte) error {
	dir := filepath.Dir(path)
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+"."+hex.EncodeToString(rnd[:])+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if runtime.GOOS == "windows" {
		return nil // a directory can't be opened for syncing there
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
