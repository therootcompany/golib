package ipcohort

import (
	"net/http"
	"strings"
)

// HTTP middleware example
func (c *Cohort) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get client IP (basic; improve with X-Forwarded-For parsing if behind proxy)
		ip, _, _ := strings.Cut(r.RemoteAddr, ":")
		if blocked, _ := c.Contains(ip); blocked {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
