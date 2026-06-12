package main

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/honeypot/shared/defense"
	"github.com/honeypot/shared/events"
	"github.com/honeypot/shared/runtime"
)

var (
	guard    *defense.Guard
	sessions *defense.SessionStore
)

func main() {
	runtime.AssertProductionSafe()
	service := runtime.Env("SERVICE_NAME", "honeypot-api")
	port := runtime.Env("PORT", "8081")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	redisBundle, err := runtime.InitHoneypotRedis(ctx, service)
	if err != nil {
		log.Fatalf("init redis: %v", err)
	}
	defer redisBundle.Close()
	logger := redisBundle.Logger
	guard = defense.NewGuard(redisBundle.Defense)
	sessions = defense.NewSessionStore(redisBundle.Defense)
	defense.SetSessionStore(sessions)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/", handleAPI(logger))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy", "service": service})
	})

	srv := &http.Server{
		Addr: ":" + port, Handler: mux,
		ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
	}

	go func() {
		log.Printf(`{"ts":"%s","svc":"%s","level":"INFO","msg":"listening on :%s"}`, time.Now().Format(time.RFC3339), service, port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
}

func handleAPI(logger *events.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := events.ClientIP(r)
		path := r.URL.Path
		payload := events.ReadBody(w, r, 65536)
		for k, v := range events.QueryParams(r) {
			payload["query_"+k] = v
		}

		status := http.StatusOK
		var response interface{}

		switch {
		case path == "/api/v1/users" && r.Method == http.MethodGet:
			response = fakeUsers(ip)
		case path == "/api/v1/users" && r.Method == http.MethodPost:
			status = http.StatusForbidden
			response = map[string]interface{}{
				"error":   "employee_provisioning_disabled",
				"message": "User creation is restricted to HR workflows.",
			}
		case strings.HasPrefix(path, "/api/v1/users/"):
			response = fakeUserDetail(path, ip)
		case path == "/api/v1/search":
			response = fakeSearch(payload, ip)
		case path == "/api/v1/config":
			response = fakeConfig(r)
		case path == "/api/v1/orders" && r.Method == http.MethodGet:
			response = fakeOrders(ip)
		case path == "/api/v1/orders" && r.Method == http.MethodPost:
			status = http.StatusAccepted
			response = map[string]interface{}{"order_id": "ORD-" + generateRequestID(), "status": "processing"}
		case path == "/api/v1/webhooks" && r.Method == http.MethodGet:
			response = fakeWebhooks()
		case path == "/api/v1/webhooks" && r.Method == http.MethodPost:
			status = http.StatusCreated
			response = map[string]interface{}{"id": "wh_" + generateRequestID(), "status": "registered", "verify": false}
		case path == "/api/v1/ldap/users":
			response = map[string]interface{}{
				"domain": "ldap.internal.acmecorp.com",
				"users": []map[string]interface{}{
					{"dn": "cn=admin,ou=users,dc=acmecorp,dc=com", "mail": "admin@acmecorp.com", "memberOf": []string{"admins"}},
					{"dn": "cn=deploy,ou=svc,dc=acmecorp,dc=com", "mail": "deploy@acmecorp.com", "memberOf": []string{"deployers"}},
				},
			}
		case path == "/api/v1/internal/debug":
			response, status = gatedInternalDebug(r, ip)
		case path == "/api/v1/billing/invoices":
			response = fakeInvoices(ip)
		case path == "/api/v1/health":
			response = map[string]string{"status": "healthy", "version": "3.2.1"}
		case path == "/api/v1/me":
			response = fakeMe(r, ip)
		case path == "/api/v1/auth/token" && r.Method == http.MethodPost:
			response, status = handleTokenGrant(r, ip, payload)
		case path == "/api/v1/metrics":
			response = map[string]interface{}{
				"requests_total": 2847193 + ipHash(ip)%10000,
				"errors_5xx":     42 + ipHash(ip)%20,
				"latency_p99_ms": 180 + ipHash(ip)%120,
				"active_sessions": 1284 + ipHash(ip)%50,
			}
		case path == "/api/v1/upload" && r.Method == http.MethodPost:
			status = http.StatusAccepted
			response = map[string]interface{}{
				"upload_id": "upl_" + generateRequestID(),
				"status":    "queued",
				"scan":      "pending",
			}
		case path == "/api/v1/files":
			response = []map[string]interface{}{
				{"id": "doc-101", "name": "Q4-Financial-Report.pdf", "size": 2840192, "owner": "c.lee@acmecorp.com"},
				{"id": "doc-102", "name": "employee-export-2026.csv", "size": 891204, "owner": "admin@acmecorp.com"},
				{"id": "doc-103", "name": "api-keys-backup.json", "size": 4096, "owner": "deploy@acmecorp.com", "restricted": true},
			}
		case path == "/api/v1/docs":
			handleAPIDocs(w, r, logger, ip, payload)
			return
		case path == "/api/v1/graphql" && r.Method == http.MethodPost:
			response = handleGraphQL(payload)
		case path == "/api/v1/secrets":
			status = http.StatusForbidden
			response = map[string]interface{}{
				"error": "forbidden", "code": "ACCESS_DENIED",
				"message": "Insufficient privileges.",
			}
		case path == "/api/v1/admin/export" && r.Method == http.MethodGet:
			response, status = gatedAdminExport(r, ip)
		case strings.HasPrefix(path, "/api/v1/users/") && (r.Method == http.MethodDelete || r.Method == http.MethodPatch):
			status = http.StatusForbidden
			response = map[string]string{"error": "insufficient privileges", "required_role": "admin"}
		default:
			status = http.StatusNotFound
			response = map[string]string{"error": "not found", "code": "RESOURCE_NOT_FOUND", "docs": "https://api.acmecorp.com/v1/docs"}
		}

		if status == http.StatusForbidden {
			if respMap, ok := response.(map[string]interface{}); ok {
				if respMap["code"] == "WAF_BLOCKED" {
					payload["waf_blocked"] = true
				}
			}
		}

		_ = logger.Log(r.Context(), events.Event{
			IP: ip, Method: r.Method, Endpoint: path,
			Payload: payload, UserAgent: r.UserAgent(), StatusCode: status,
		})

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-API-Version", "3.2.1")
		w.Header().Set("X-Request-Id", generateRequestID())
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", 100-ipHash(ip)%20))
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(response)
	}
}

func ipHash(ip string) int {
	h := fnv.New32a()
	h.Write([]byte(ip))
	return int(h.Sum32())
}

func fakeUsers(ip string) []map[string]interface{} {
	variants := [][]map[string]interface{}{
		{
			{"id": 1, "email": "admin@acmecorp.com", "role": "admin", "active": true, "department": "Engineering"},
			{"id": 2, "email": "j.smith@acmecorp.com", "role": "editor", "active": true, "department": "Marketing"},
			{"id": 3, "email": "m.jones@acmecorp.com", "role": "viewer", "active": false, "department": "Sales"},
		},
		{
			{"id": 10, "email": "c.lee@acmecorp.com", "role": "admin", "active": true, "department": "Finance"},
			{"id": 11, "email": "a.patel@acmecorp.com", "role": "editor", "active": true, "department": "Ops"},
			{"id": 12, "email": "guest@acmecorp.com", "role": "viewer", "active": true, "department": "External"},
		},
	}
	return variants[ipHash(ip)%len(variants)]
}

func fakeUserDetail(path string, ip string) map[string]interface{} {
	return map[string]interface{}{
		"id": path, "email": "user@acmecorp.com", "role": "editor",
		"last_login": time.Now().Add(-time.Duration(ipHash(ip)%48) * time.Hour).Format(time.RFC3339),
		"mfa_enabled": ipHash(ip)%2 == 0,
	}
}

func fakeSearch(payload map[string]interface{}, ip string) map[string]interface{} {
	q, _ := payload["query"].(string)
	if q == "" {
		q, _ = payload["query_q"].(string)
	}
	titles := []string{"Q4 Financial Report", "Employee Handbook v4", "API Integration Guide",
		"Security Audit 2026", "Customer Data Export Policy"}
	start := ipHash(ip) % 3
	return map[string]interface{}{
		"query": q, "total": 5,
		"results": []map[string]string{
			{"id": "doc-101", "title": titles[start%len(titles)]},
			{"id": "doc-102", "title": titles[(start+1)%len(titles)]},
			{"id": "doc-103", "title": titles[(start+2)%len(titles)]},
		},
		"took_ms": 12 + ipHash(ip)%30,
	}
}

func fakeConfig(r *http.Request) map[string]interface{} {
	cfg := map[string]interface{}{
		"version": "3.2.1", "environment": "production",
		"features": []string{"sso", "audit", "billing", "webhooks"},
		"regions":  []string{"us-east-1", "eu-west-1", "ap-southeast-1"},
		"maintenance_window": "Sun 02:00-04:00 UTC",
	}
	if defense.HasAuth(r) {
		cfg["_deploy_key"] = defense.HoneyAWSKey
	}
	return cfg
}

func gatedInternalDebug(r *http.Request, ip string) (interface{}, int) {
	ctx := r.Context()
	hasBearer := defense.HasBearer(r)
	hasLDAP := guard.HasLDAPPivot(ctx, ip)
	tier := guard.ResolveTrapTier(ctx, ip, "api_internal_debug", true, defense.HasAuth(r))

	if tier == 0 {
		return map[string]interface{}{
			"error": "forbidden", "code": "WAF_BLOCKED",
			"message": "Request blocked by edge protection",
		}, http.StatusForbidden
	}
	if !hasBearer && !hasLDAP {
		return map[string]interface{}{
			"error": "forbidden", "code": "UNAUTHORIZED",
			"message": "Access denied.",
		}, http.StatusForbidden
	}
	if tier == 1 && !hasLDAP {
		return map[string]interface{}{
			"error": "forbidden", "code": "UNAUTHORIZED",
			"message": "Access denied.",
		}, http.StatusForbidden
	}
	return map[string]interface{}{
		"status": "debug", "environment": "production",
		"database_host": "db.internal.acmecorp.com",
		"api_key": defense.HoneyAPIKey, "deploy_key": defense.HoneyAWSKey,
		"jwt_secret": defense.JWTSecret,
	}, http.StatusOK
}

func handleTokenGrant(r *http.Request, ip string, payload map[string]interface{}) (interface{}, int) {
	grant, _ := payload["grant_type"].(string)
	switch grant {
	case "client_credentials":
		clientID, _ := payload["client_id"].(string)
		secret, _ := payload["client_secret"].(string)
		if !defense.ValidOAuthClient(clientID, secret) {
			return map[string]interface{}{
				"error": "invalid_client", "error_description": "Invalid client credentials.",
			}, http.StatusUnauthorized
		}
		token, err := sessions.IssueBearer(r.Context(), ip, "oauth:client")
		if err != nil {
			return map[string]interface{}{"error": "server_error"}, http.StatusServiceUnavailable
		}
		return map[string]interface{}{
			"access_token": token, "token_type": "Bearer", "expires_in": 3600,
			"scope": "internal:debug",
		}, http.StatusOK
	case "password":
		username, _ := payload["username"].(string)
		password, _ := payload["password"].(string)
		if defense.ValidLDAPBind(username, password) || (username == "deploy@acmecorp.com" && password == defense.LDAPDeployPass) {
			guard.MarkLDAPPivot(r.Context(), ip)
			token, err := sessions.IssueBearer(r.Context(), ip, "ldap:service")
			if err != nil {
				return map[string]interface{}{"error": "server_error"}, http.StatusServiceUnavailable
			}
			return map[string]interface{}{
				"access_token": token, "token_type": "Bearer", "expires_in": 3600,
				"scope": "service:read",
			}, http.StatusOK
		}
	}
	return map[string]interface{}{
		"error":             "invalid_grant",
		"error_description": "The provided credentials are invalid.",
	}, http.StatusUnauthorized
}

func gatedAdminExport(r *http.Request, ip string) (interface{}, int) {
	if !defense.HasAdminSession(r) {
		tier := guard.ResolveTrapTier(r.Context(), ip, "api_admin_export", true, false)
		if tier == 0 {
			return map[string]interface{}{
				"error": "forbidden", "code": "WAF_BLOCKED",
			}, http.StatusForbidden
		}
		return map[string]interface{}{
			"error": "insufficient privileges", "required_role": "admin", "login": "/login",
		}, http.StatusForbidden
	}
	if !guard.HasWeakCred(r.Context(), ip) && guard.ProbeCount(r.Context(), ip, "api_admin_export") < 2 {
		guard.IncProbe(r.Context(), ip, "api_admin_export")
		return map[string]interface{}{
			"error": "export requires security review approval",
			"ticket": "SEC-REVIEW-REQUIRED",
		}, http.StatusForbidden
	}
	return map[string]interface{}{
		"users": fakeUsers(ip), "exported_at": time.Now().Format(time.RFC3339),
		"deploy_key": defense.HoneyAWSKey,
	}, http.StatusOK
}

func fakeOrders(ip string) []map[string]interface{} {
	return []map[string]interface{}{
		{"id": "ORD-1001", "customer": "Acme Industries", "amount": 4299.00, "status": "shipped"},
		{"id": "ORD-1002", "customer": "Globex Corp", "amount": 1899.50, "status": "pending"},
		{"id": fmt.Sprintf("ORD-%d", 1000+ipHash(ip)%900), "customer": "Initech", "amount": 750.00, "status": "delivered"},
	}
}

func fakeWebhooks() []map[string]interface{} {
	return []map[string]interface{}{
		{"id": "wh_01", "url": "https://hooks.acmecorp.com/events", "events": []string{"order.created", "user.updated"}, "secret": defense.HoneyStripeKey},
		{"id": "wh_02", "url": "https://internal.acmecorp.com/notify", "events": []string{"payment.failed"}, "active": true},
	}
}

func fakeMe(r *http.Request, ip string) map[string]interface{} {
	role := defense.SessionRole(r)
	if role == "" {
		return map[string]interface{}{"authenticated": false, "error": "session_expired", "login": "/login"}
	}
	email := "contractor@acmecorp.com"
	perms := []string{"storage:read"}
	if role == defense.RoleAdmin {
		email = "admin@acmecorp.com"
		perms = []string{"admin:read", "admin:write", "billing:view"}
	}
	return map[string]interface{}{
		"id": "usr_1", "email": email, "name": "Acme User", "role": role,
		"tenant": "acmecorp", "mfa_enabled": role == defense.RoleAdmin, "session_ip": ip,
		"permissions": perms,
	}
}

func fakeInvoices(ip string) []map[string]interface{} {
	return []map[string]interface{}{
		{"id": "INV-2026-001", "amount": 12500.00, "status": "paid", "due": "2026-05-01"},
		{"id": fmt.Sprintf("INV-2026-%03d", ipHash(ip)%100), "amount": 3200.00, "status": "open", "due": "2026-07-01"},
	}
}

func generateRequestID() string {
	return time.Now().Format("20060102150405") + "-api"
}

func handleGraphQL(payload map[string]interface{}) map[string]interface{} {
	query, _ := payload["query"].(string)
	if strings.Contains(strings.ToLower(query), "__schema") || strings.Contains(strings.ToLower(query), "introspection") {
		return map[string]interface{}{
			"data": map[string]interface{}{
				"__schema": map[string]interface{}{
					"types": []map[string]interface{}{
						{"name": "User", "fields": []map[string]string{{"name": "email"}, {"name": "apiKey"}, {"name": "internalNotes"}}},
						{"name": "Query", "fields": []map[string]string{{"name": "users"}, {"name": "internalDebug"}, {"name": "exportAll"}}},
					},
				},
			},
		}
	}
	return map[string]interface{}{
		"errors": []map[string]string{{"message": "Introspection is disabled."}},
	}
}

func handleAPIDocs(w http.ResponseWriter, r *http.Request, logger *events.Logger, ip string, payload map[string]interface{}) {
	_ = logger.Log(r.Context(), events.Event{
		IP: ip, Method: r.Method, Endpoint: "/api/v1/docs",
		Payload: payload, UserAgent: r.UserAgent(), StatusCode: 200,
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`<!DOCTYPE html><html><head><title>AcmeCorp API v3.2</title>
<style>body{font-family:system-ui;max-width:800px;margin:40px auto;padding:0 20px;background:#0f172a;color:#e2e8f0}
code{background:#1e293b;padding:2px 6px;border-radius:4px}</style></head><body>
<h1>AcmeCorp REST API</h1>
<p>Base URL: <code>/api/v1</code></p>
<ul>
<li><code>GET /users</code> — list users</li>
<li><code>GET /config</code> — service configuration</li>
<li><code>GET /internal/debug</code> — internal diagnostics (restricted)</li>
<li><code>POST /graphql</code> — GraphQL gateway</li>
<li><code>GET /admin/export</code> — bulk export (admin)</li>
</ul>
<p>Authentication: Bearer token or session cookie. See <code>/login</code>.</p>
</body></html>`))
}

