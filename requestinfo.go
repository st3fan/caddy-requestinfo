// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

package requestinfo

import (
	"encoding/json"
	"net/http"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

type RequestInfo struct {
	Next httpserver.Handler
	Path string
}

type RequestInfoResponse struct {
	Address  string
	Method   string
	Protocol string
	Headers  map[string][]string
}

func protocol(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	} else {
		return "http"
	}
}

func (h RequestInfo) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	if r.URL.Path == h.Path {
		requestInfoResponse := RequestInfoResponse{
			Address:  r.RemoteAddr,
			Method:   r.Method,
			Protocol: protocol(r),
			Headers:  r.Header,
		}
		w.Header().Add("Content-Type", "application/json")
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "   ")
		encoder.Encode(requestInfoResponse)
		return 0, nil
	}
	return h.Next.ServeHTTP(w, r)
}
