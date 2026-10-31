// Command fixture is the private HTTP service the live end-to-end test
// publishes. It echoes what it receives, so the test can see exactly what a
// service behind the tunnel gets.
//
//	GET  /big   32 MiB of zeros
//	GET  /...   JSON {"path": ..., "headers": {...}}
//	POST /...   JSON {"bytes": n, "sha256": hex}
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"strings"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18081", "listen address")
	flag.Parse()
	log.Fatal(http.ListenAndServe(*addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		switch {
		case r.Method == http.MethodPost:
			h := sha256.New()
			n, _ := io.Copy(h, r.Body)
			_ = json.NewEncoder(w).Encode(map[string]any{"bytes": n, "sha256": hex.EncodeToString(h.Sum(nil))})
		case r.URL.Path == "/big":
			w.Header().Set("Content-Length", "33554432")
			_, _ = io.CopyN(w, zeros{}, 32<<20)
		default:
			headers := map[string]string{"Host": r.Host}
			for k, v := range r.Header {
				headers[k] = strings.Join(v, ", ")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"path": r.URL.RequestURI(), "headers": headers})
		}
	})))
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }
