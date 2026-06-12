package defense

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	LoginLockThreshold = 5
	MFALockThreshold   = 5
	LoginLockTTL       = 15 * time.Minute
	MFALockTTL         = 10 * time.Minute
)

type Guard struct {
	rdb *redis.Client
}

func NewGuard(rdb *redis.Client) *Guard {
	return &Guard{rdb: rdb}
}

func (g *Guard) Allow(ctx context.Context, ip, bucket string, limit int, window time.Duration) (allowed bool, remaining int) {
	if g == nil || g.rdb == nil {
		return true, limit
	}
	key := fmt.Sprintf("defense:%s:%s:%s", bucket, ip, time.Now().Unix()/int64(window.Seconds()))
	n, err := g.rdb.Incr(ctx, key).Result()
	if err != nil {
		return true, limit
	}
	if n == 1 {
		_ = g.rdb.Expire(ctx, key, window).Err()
	}
	remaining = limit - int(n)
	return n <= int64(limit), remaining
}

func (g *Guard) IncProbe(ctx context.Context, ip, trap string) int {
	if g == nil || g.rdb == nil {
		return 1
	}
	key := fmt.Sprintf("defense:probe:%s:%s", ip, trap)
	n, _ := g.rdb.Incr(ctx, key).Result()
	if n == 1 {
		_ = g.rdb.Expire(ctx, key, 24*time.Hour).Err()
	}
	totalKey := fmt.Sprintf("defense:probe_total:%s", ip)
	total, _ := g.rdb.Incr(ctx, totalKey).Result()
	if total == 1 {
		_ = g.rdb.Expire(ctx, totalKey, 24*time.Hour).Err()
	}
	return int(n)
}

func (g *Guard) ProbeCount(ctx context.Context, ip, trap string) int {
	if g == nil || g.rdb == nil {
		return 0
	}
	n, _ := g.rdb.Get(ctx, fmt.Sprintf("defense:probe:%s:%s", ip, trap)).Int()
	return n
}

func (g *Guard) TotalProbes(ctx context.Context, ip string) int {
	if g == nil || g.rdb == nil {
		return 0
	}
	n, _ := g.rdb.Get(ctx, fmt.Sprintf("defense:probe_total:%s", ip)).Int()
	return n
}

func (g *Guard) MarkWeakCred(ctx context.Context, ip string) {
	if g == nil || g.rdb == nil {
		return
	}
	key := fmt.Sprintf("defense:weak_cred:%s", ip)
	_ = g.rdb.Set(ctx, key, "1", 2*time.Hour).Err()
}

func (g *Guard) HasWeakCred(ctx context.Context, ip string) bool {
	if g == nil || g.rdb == nil {
		return false
	}
	v, _ := g.rdb.Get(ctx, fmt.Sprintf("defense:weak_cred:%s", ip)).Result()
	return v == "1"
}

func (g *Guard) IncLoginFail(ctx context.Context, ip string) (count int, locked bool) {
	return g.incFail(ctx, ip, "login_fail", LoginLockThreshold, LoginLockTTL)
}

func (g *Guard) IncMFAFail(ctx context.Context, ip string) (count int, locked bool) {
	return g.incFail(ctx, ip, "mfa_fail", MFALockThreshold, MFALockTTL)
}

func (g *Guard) IsLoginLocked(ctx context.Context, ip string) bool {
	return g.isLocked(ctx, ip, "login_lock")
}

func (g *Guard) IsMFALocked(ctx context.Context, ip string) bool {
	return g.isLocked(ctx, ip, "mfa_lock")
}

// ClearAuthFails resets login/MFA failure counters and lockouts after successful auth steps.
func (g *Guard) ClearAuthFails(ctx context.Context, ip string) {
	if g == nil || g.rdb == nil {
		return
	}
	keys := []string{
		fmt.Sprintf("defense:login_fail:%s", ip),
		fmt.Sprintf("defense:login_lock:%s", ip),
		fmt.Sprintf("defense:mfa_fail:%s", ip),
		fmt.Sprintf("defense:mfa_lock:%s", ip),
	}
	_ = g.rdb.Del(ctx, keys...).Err()
}

func (g *Guard) incFail(ctx context.Context, ip, kind string, threshold int, lockTTL time.Duration) (int, bool) {
	if g == nil || g.rdb == nil {
		return 0, false
	}
	failKey := fmt.Sprintf("defense:%s:%s", kind, ip)
	n, _ := g.rdb.Incr(ctx, failKey).Result()
	if n == 1 {
		_ = g.rdb.Expire(ctx, failKey, lockTTL).Err()
	}
	if int(n) >= threshold {
		lockKey := fmt.Sprintf("defense:login_lock:%s", ip)
		if kind == "mfa_fail" {
			lockKey = fmt.Sprintf("defense:mfa_lock:%s", ip)
		}
		_ = g.rdb.Set(ctx, lockKey, "1", lockTTL).Err()
		return int(n), true
	}
	return int(n), false
}

func (g *Guard) isLocked(ctx context.Context, ip, lockKind string) bool {
	if g == nil || g.rdb == nil {
		return false
	}
	v, _ := g.rdb.Get(ctx, fmt.Sprintf("defense:%s:%s", lockKind, ip)).Result()
	return v == "1"
}

// ResolveTrapTier returns 0=WAF block, 1=partial leak, 2=full bait.
func (g *Guard) ResolveTrapTier(ctx context.Context, ip, trap string, sensitive, session bool) int {
	if !sensitive {
		return 2
	}
	probes := g.IncProbe(ctx, ip, trap)
	total := g.TotalProbes(ctx, ip)
	weak := g.HasWeakCred(ctx, ip)

	if probes <= 1 && total < 2 {
		return 0
	}
	if probes >= 5 || (weak && probes >= 3) || (session && weak && probes >= 2) {
		return 2
	}
	if probes >= 2 || total >= 3 || weak || session {
		return 1
	}
	return 0
}

const WAFBody = `<!DOCTYPE html><html><head><title>403 Forbidden</title>
<style>body{font-family:system-ui;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.box{max-width:480px;padding:32px;border:1px solid #334155;border-radius:8px;background:#1e293b}
h1{font-size:20px;margin:0 0 8px}p{color:#94a3b8;font-size:14px;margin:0}</style></head>
<body><div class="box"><h1>403 — Request Blocked</h1>
<p>AcmeCorp WAF · Rule: sensitive-path-protection · Incident ref logged.</p></div></body></html>`

func (g *Guard) MarkLDAPPivot(ctx context.Context, ip string) {
	if g == nil || g.rdb == nil {
		return
	}
	_ = g.rdb.Set(ctx, fmt.Sprintf("defense:ldap_pivot:%s", ip), "1", 2*time.Hour).Err()
}

func (g *Guard) HasLDAPPivot(ctx context.Context, ip string) bool {
	if g == nil || g.rdb == nil {
		return false
	}
	v, _ := g.rdb.Get(ctx, fmt.Sprintf("defense:ldap_pivot:%s", ip)).Result()
	return v == "1"
}

