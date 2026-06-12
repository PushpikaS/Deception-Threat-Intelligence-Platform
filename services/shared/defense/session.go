package defense

import (
	"net/http"
	"strings"
)

const SessionCookie = "acme_session"

func sessionToken(r *http.Request) string {
	c, err := r.Cookie(SessionCookie)
	if err != nil || c.Value == "" || c.Value == "authenticated" {
		return ""
	}
	return c.Value
}

func SessionRole(r *http.Request) string {
	if defaultStore == nil {
		return ""
	}
	role, ok := defaultStore.Validate(r.Context(), sessionToken(r))
	if !ok {
		return ""
	}
	return role
}

func HasSession(r *http.Request) bool {
	return SessionRole(r) != ""
}

func HasAdminSession(r *http.Request) bool {
	return SessionRole(r) == RoleAdmin
}

func HasViewerOrAdmin(r *http.Request) bool {
	role := SessionRole(r)
	return role == RoleAdmin || role == RoleViewer
}

func HasBearer(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return false
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	if token == "" {
		return false
	}
	if defaultStore == nil {
		return ValidAPIKey(token)
	}
	return defaultStore.ValidateBearer(r.Context(), token) || ValidAPIKey(token)
}

func HasAuth(r *http.Request) bool {
	return HasSession(r) || HasBearer(r)
}