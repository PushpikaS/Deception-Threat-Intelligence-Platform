package runtime

import (
	"context"

	"github.com/honeypot/shared/events"
	"github.com/redis/go-redis/v9"
)

// HoneypotRedis holds dedicated Redis clients for event publishing and defense state.
type HoneypotRedis struct {
	Logger  *events.Logger
	Defense *redis.Client
}

// InitHoneypotRedis connects event-stream and defense/session Redis instances.
func InitHoneypotRedis(ctx context.Context, service string) (*HoneypotRedis, error) {
	eventsURL := Env("REDIS_EVENTS_URL", "redis://localhost:6379/0")
	defenseURL := Env("REDIS_DEFENSE_URL", "redis://localhost:6379/1")

	logger, err := events.NewLogger(ctx, eventsURL, service)
	if err != nil {
		return nil, err
	}
	defenseRdb, err := events.ConnectRedis(ctx, defenseURL)
	if err != nil {
		logger.Close()
		return nil, err
	}
	return &HoneypotRedis{Logger: logger, Defense: defenseRdb}, nil
}

// Close releases Redis connections.
func (h *HoneypotRedis) Close() {
	if h == nil {
		return
	}
	h.Logger.Close()
	if h.Defense != nil {
		_ = h.Defense.Close()
	}
}