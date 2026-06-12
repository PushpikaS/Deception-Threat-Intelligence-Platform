package runtime

import (
	"log"
	"strings"
)

// AssertProductionSafe exits when STRICT_PRODUCTION is enabled and known weak defaults remain.
func AssertProductionSafe() {
	if Env("STRICT_PRODUCTION", "") != "true" && Env("STRICT_PRODUCTION", "") != "1" {
		return
	}
	redisPass := Env("REDIS_PASSWORD", "changeme_redis_local")
	if redisPass == "" || redisPass == "changeme_redis_local" {
		log.Fatalf("STRICT_PRODUCTION: REDIS_PASSWORD must not use the development default")
	}
	for _, key := range []string{"REDIS_EVENTS_URL", "REDIS_DEFENSE_URL"} {
		redisURL := Env(key, "")
		if redisURL == "" {
			continue
		}
		if strings.Contains(redisURL, "changeme_redis_local") {
			log.Fatalf("STRICT_PRODUCTION: %s must not use the default Redis password", key)
		}
	}
}