package events

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const EventStream = "honeypot:events"

type Event struct {
	Service    string
	IP         string
	Method     string
	Endpoint   string
	Payload    map[string]interface{}
	UserAgent  string
	StatusCode int
}

// Logger publishes honeypot events to Redis Stream (event bus).
// postgres-events ingestion is handled by threat-ingest — decoupled microservice boundary.
type Logger struct {
	redis   *redis.Client
	service string
}

func NewLogger(ctx context.Context, redisURL, service string) (*Logger, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	rdb := redis.NewClient(opt)

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("ping redis: %w", err)
	}

	return &Logger{redis: rdb, service: service}, nil
}

func (l *Logger) Redis() *redis.Client {
	return l.redis
}

func (l *Logger) Close() {
	if l.redis != nil {
		l.redis.Close()
	}
}

func (l *Logger) Log(ctx context.Context, evt Event) error {
	if evt.Service == "" {
		evt.Service = l.service
	}
	if evt.StatusCode == 0 {
		evt.StatusCode = 200
	}
	if evt.Payload == nil {
		evt.Payload = map[string]interface{}{}
	}

	payloadJSON, err := json.Marshal(evt.Payload)
	if err != nil {
		return err
	}

	if err := l.redis.XAdd(ctx, &redis.XAddArgs{
		Stream: EventStream,
		Values: map[string]interface{}{
			"service":     evt.Service,
			"ip":          evt.IP,
			"method":      evt.Method,
			"endpoint":    evt.Endpoint,
			"payload":     string(payloadJSON),
			"user_agent":  evt.UserAgent,
			"status_code": evt.StatusCode,
			"ts":          time.Now().UTC().Format(time.RFC3339Nano),
		},
	}).Err(); err != nil {
		return fmt.Errorf("xadd %s: %w", EventStream, err)
	}

	key := fmt.Sprintf("ip:%s:requests", evt.IP)
	pipe := l.redis.Pipeline()
	pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, 24*time.Hour)
	pipe.SAdd(ctx, fmt.Sprintf("ip:%s:services", evt.IP), evt.Service)
	pipe.Expire(ctx, fmt.Sprintf("ip:%s:services", evt.IP), 24*time.Hour)
	_, _ = pipe.Exec(ctx)

	return nil
}

func ClientIP(r *http.Request) string {
	for _, header := range []string{"CF-Connecting-IP", "True-Client-IP", "X-Real-IP"} {
		if ip := strings.TrimSpace(r.Header.Get(header)); ip != "" {
			return ip
		}
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func ReadBody(w http.ResponseWriter, r *http.Request, maxBytes int64) map[string]interface{} {
	result := map[string]interface{}{}
	if r.Body == nil {
		return result
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	defer r.Body.Close()

	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
		for k, v := range body {
			if isSensitiveKey(k) {
				result[k] = "[REDACTED]"
			} else {
				result[k] = v
			}
		}
	}
	return result
}

func isSensitiveKey(k string) bool {
	k = strings.ToLower(k)
	sensitive := []string{"password", "passwd", "secret", "token", "api_key", "apikey"}
	for _, s := range sensitive {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

func QueryParams(r *http.Request) map[string]interface{} {
	params := map[string]interface{}{}
	for k, v := range r.URL.Query() {
		if len(v) == 1 {
			params[k] = v[0]
		} else {
			params[k] = v
		}
	}
	return params
}