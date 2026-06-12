package runtime

import "strings"

// CookieSecure reports whether HttpOnly session cookies should include the Secure flag.
func CookieSecure() bool {
	switch strings.ToLower(Env("COOKIE_SECURE", "true")) {
	case "0", "false", "no":
		return false
	default:
		return true
	}
}