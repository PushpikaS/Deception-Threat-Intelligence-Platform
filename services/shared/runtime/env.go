package runtime

import "os"

// Env returns the environment variable or fallback when unset.
func Env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}