//go:build linux

// Copyright 2026 MMXlabs & LQC LLC
// SPDX-License-Identifier: Apache-2.0
package node

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// RPCBrowserOptions is an opt-in exact Origin allowlist. Zero value preserves
// the original non-browser policy. Wildcards, remote hosts and credentials are
// never accepted; loopback binding is independent of this allowlist.
type RPCBrowserOptions struct{ AllowedOrigins []string }

func browserOrigins(opts RPCBrowserOptions) (map[string]bool, error) {
	if len(opts.AllowedOrigins) > 16 {
		return nil, fmt.Errorf("too many local Origins")
	}
	out := map[string]bool{}
	for _, origin := range opts.AllowedOrigins {
		u, e := url.Parse(origin)
		if e != nil || u == nil {
			return nil, fmt.Errorf("invalid local Origin")
		}
		host := u.Hostname()
		port := u.Port()
		if (u.Scheme != "http" && u.Scheme != "https") || (host != "localhost" && host != "127.0.0.1") || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || origin != u.Scheme+"://"+u.Host || (port == "" && u.Host != host) {
			return nil, fmt.Errorf("exact local Origin required")
		}
		if port != "" {
			p, e := strconv.Atoi(port)
			if e != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid Origin port")
			}
		}
		out[origin] = true
	}
	return out, nil
}

func localRPCHandler(next http.Handler, origins map[string]bool) http.Handler {
	slots := make(chan struct{}, 8)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		origin := r.Header.Get("Origin")
		if (host != "127.0.0.1" && host != "localhost") || len(r.Header.Values("Origin")) > 1 || (len(r.Header.Values("Origin")) == 1 && origin == "") || (origin != "" && !origins[origin]) {
			http.Error(w, "local RPC requests only", http.StatusForbidden)
			return
		}
		w.Header().Add("Vary", "Origin")
		if r.URL.Path != "/" {
			http.Error(w, "RPC path required", http.StatusNotFound)
			return
		}
		if r.Method == http.MethodOptions {
			w.Header().Add("Vary", "Access-Control-Request-Method")
			w.Header().Add("Vary", "Access-Control-Request-Headers")
			if origin == "" || len(r.Header.Values("Access-Control-Request-Method")) != 1 || len(r.Header.Values("Access-Control-Request-Headers")) > 1 || r.Header.Get("Access-Control-Request-Method") != "POST" || r.Header.Get("Access-Control-Request-Private-Network") != "" {
				http.Error(w, "invalid preflight", http.StatusForbidden)
				return
			}
			for _, h := range strings.Split(r.Header.Get("Access-Control-Request-Headers"), ",") {
				if h = strings.TrimSpace(h); h != "" && !strings.EqualFold(h, "content-type") {
					http.Error(w, "invalid preflight header", http.StatusForbidden)
					return
				}
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "POST")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Access-Control-Request-Method") != "" {
			http.Error(w, "invalid preflight", http.StatusForbidden)
			return
		}
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "RPC busy", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}
