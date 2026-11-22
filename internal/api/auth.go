package api

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// RequireBearer rejects requests without "Authorization: Bearer <token>".
// Remote serves use it so a reachable listener is not anonymous.
func RequireBearer(h http.Handler, token string) http.Handler {
	const scheme = "Bearer "
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimSpace(r.Header.Get("Authorization"))
		if len(got) <= len(scheme) || !strings.EqualFold(got[:len(scheme)], scheme) ||
			subtle.ConstantTimeCompare([]byte(got[len(scheme):]), []byte(token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="cv3"`)
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		h.ServeHTTP(w, r)
	})
}
