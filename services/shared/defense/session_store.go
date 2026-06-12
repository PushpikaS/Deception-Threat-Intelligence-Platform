package defense

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/honeypot/shared/runtime"
)

const (
	RoleAdmin   = "admin"
	RoleViewer  = "viewer"
	RoleService = "service"

	sessionTTL = 2 * time.Hour
	bearerTTL  = 1 * time.Hour
)

type SessionStore struct {
	rdb *redis.Client
}

var defaultStore *SessionStore

func NewSessionStore(rdb *redis.Client) *SessionStore {
	return &SessionStore{rdb: rdb}
}

func SetSessionStore(s *SessionStore) {
	defaultStore = s
}

func (s *SessionStore) Create(ctx context.Context, ip, role string) (string, error) {
	if s == nil || s.rdb == nil {
		return "", fmt.Errorf("session store unavailable")
	}
	token, err := randomToken(24)
	if err != nil {
		return "", err
	}
	key := fmt.Sprintf("defense:session:%s", token)
	pipe := s.rdb.Pipeline()
	pipe.HSet(ctx, key, map[string]interface{}{
		"role": role, "ip": ip, "created": time.Now().Unix(),
	})
	pipe.Expire(ctx, key, sessionTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		return "", err
	}
	return token, nil
}

func (s *SessionStore) Validate(ctx context.Context, token string) (role string, ok bool) {
	if s == nil || s.rdb == nil || token == "" {
		return "", false
	}
	vals, err := s.rdb.HGetAll(ctx, fmt.Sprintf("defense:session:%s", token)).Result()
	if err != nil || len(vals) == 0 {
		return "", false
	}
	return vals["role"], vals["role"] != ""
}

func (s *SessionStore) IssueBearer(ctx context.Context, ip, scope string) (string, error) {
	if s == nil || s.rdb == nil {
		return "", fmt.Errorf("session store unavailable")
	}
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	key := fmt.Sprintf("defense:bearer:%s", token)
	if err := s.rdb.Set(ctx, key, scope+"|"+ip, bearerTTL).Err(); err != nil {
		return "", err
	}
	return "atk_" + token, nil
}

func (s *SessionStore) ValidateBearer(ctx context.Context, token string) bool {
	if ValidAPIKey(token) {
		return true
	}
	if s == nil || s.rdb == nil {
		return false
	}
	if len(token) > 4 && token[:4] == "atk_" {
		token = token[4:]
	}
	v, err := s.rdb.Get(ctx, fmt.Sprintf("defense:bearer:%s", token)).Result()
	return err == nil && v != ""
}

func (s *SessionStore) Invalidate(ctx context.Context, token string) {
	if s == nil || s.rdb == nil || token == "" {
		return
	}
	_ = s.rdb.Del(ctx, fmt.Sprintf("defense:session:%s", token)).Err()
}

func SetSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: token,
		Path: "/", MaxAge: int(sessionTTL.Seconds()),
		HttpOnly: true, Secure: runtime.CookieSecure(), SameSite: http.SameSiteLaxMode,
	})
}

func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: "", Path: "/", MaxAge: -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name: "acme_jwt", Value: "", Path: "/", MaxAge: -1,
	})
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}