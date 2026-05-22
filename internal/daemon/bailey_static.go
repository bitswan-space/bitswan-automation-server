package daemon

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"sync"
)

//go:embed static
var baileyStaticFS embed.FS

// staticAssetVersion returns a short content hash for a vendored
// static file ("network-map.js", "network-map.css", ...). Used as a
// ?v=<hash> query string in the script/link tags so the long
// Cache-Control TTL works correctly across rebuilds — same content =
// same URL = cached; new bundle = new URL = re-fetched.
var (
	staticVersionOnce sync.Once
	staticVersionMap  = map[string]string{}
)

func staticAssetVersion(name string) string {
	staticVersionOnce.Do(func() {
		sub, err := fs.Sub(baileyStaticFS, "static")
		if err != nil {
			return
		}
		_ = fs.WalkDir(sub, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			f, err := sub.Open(p)
			if err != nil {
				return nil
			}
			defer f.Close()
			h := sha256.New()
			if _, err := io.Copy(h, f); err != nil {
				return nil
			}
			staticVersionMap[p] = hex.EncodeToString(h.Sum(nil))[:8]
			return nil
		})
	})
	return staticVersionMap[name]
}

// handleBaileyStatic serves vendored JS/CSS from /bailey/static/*.
// Files are go:embed'd at build time. Cache aggressively because
// they're versioned-by-commit (rebuild = redeploy = new bytes).
func handleBaileyStatic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/bailey/static/")
	if path == "" || strings.Contains(path, "..") {
		http.NotFound(w, r)
		return
	}
	sub, err := fs.Sub(baileyStaticFS, "static")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	f, err := sub.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || stat.IsDir() {
		http.NotFound(w, r)
		return
	}
	switch {
	case strings.HasSuffix(path, ".js"):
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	case strings.HasSuffix(path, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	}
	w.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeContent(w, r, path, stat.ModTime(), f.(interface {
		Read([]byte) (int, error)
		Seek(int64, int) (int64, error)
	}))
}
