package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/honeypot/shared/defense"
	"github.com/honeypot/shared/events"
	"github.com/honeypot/shared/runtime"
)

func handleLDAPBind(logger *events.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := events.ClientIP(r)
		ctx := r.Context()
		payload := events.ReadBody(w, r, 4096)
		dn, _ := payload["dn"].(string)
		password, _ := payload["password"].(string)

		status := http.StatusUnauthorized
		resp := map[string]interface{}{"error": "bind failed", "code": "LDAP_BIND_FAILED"}

		if defense.ValidLDAPBind(dn, password) {
			guard.MarkLDAPPivot(ctx, ip)
			bearer, err := sessions.IssueBearer(ctx, ip, "ldap:service")
			if err != nil {
				status = http.StatusServiceUnavailable
				resp = map[string]interface{}{"error": "token issuance failed"}
			} else {
				status = http.StatusOK
				resp = map[string]interface{}{
					"status": "bind_ok", "dn": dn,
					"service_token": bearer,
				}
				payload["ldap_pivot"] = true
			}
		} else if dn != "" {
			status = http.StatusForbidden
			resp = map[string]interface{}{
				"error": "bind failed", "code": "LDAP_BIND_FAILED",
				"message": "Invalid credentials.",
			}
		}
		_ = logger.Log(r.Context(), events.Event{
			IP: ip, Method: r.Method, Endpoint: "/auth/ldap/bind",
			Payload: payload, UserAgent: r.UserAgent(), StatusCode: status,
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(resp)
	}
}

func handleLogin(logger *events.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := events.ClientIP(r)
		ctx := r.Context()
		payload := events.ReadBody(w, r, 4096)
		email, _ := payload["email"].(string)
		password, _ := payload["password"].(string)
		email = strings.ToLower(strings.TrimSpace(email))
		password = strings.TrimSpace(password)

		status := http.StatusUnauthorized
		resp := map[string]interface{}{
			"error": "Invalid credentials", "code": "AUTH_FAILED",
		}

		if guard.IsLoginLocked(ctx, ip) {
			status = http.StatusTooManyRequests
			resp = map[string]interface{}{
				"error":   "account temporarily locked",
				"code":    "ACCOUNT_LOCKED",
				"message": "Too many failed sign-in attempts. Try again in 15 minutes.",
			}
			payload["account_locked"] = true
		} else if isEmployeeEmail(email) && len(password) >= 8 {
			guard.ClearAuthFails(ctx, ip)
			status = http.StatusOK
			resp = map[string]interface{}{
				"mfa_required": true,
				"next":         "/login/mfa",
			}
			if weak, match := matchWeakCredential(email, password); weak {
				payload["weak_credential_attempt"] = true
				payload["weak_cred_match"] = match
				guard.MarkWeakCred(ctx, ip)
			}
			payload["employee_login"] = true
		} else if email != "" && strings.Contains(email, "@") {
			failCount, locked := guard.IncLoginFail(ctx, ip)
			payload["login_failures"] = failCount
			resp["message"] = "Invalid email or password."
			if locked {
				status = http.StatusTooManyRequests
				resp = map[string]interface{}{
					"error":   "account temporarily locked",
					"code":    "ACCOUNT_LOCKED",
					"message": "Too many failed sign-in attempts. Try again in 15 minutes.",
				}
			}
		} else {
			_, _ = guard.IncLoginFail(ctx, ip)
		}

		_ = logger.Log(ctx, events.Event{
			IP: ip, Method: r.Method, Endpoint: "/auth/login",
			Payload: payload, UserAgent: r.UserAgent(), StatusCode: status,
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(resp)
	}
}

func handleMFAVerify(logger *events.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := events.ClientIP(r)
		ctx := r.Context()
		payload := events.ReadBody(w, r, 4096)
		code, _ := payload["code"].(string)
		redirect, _ := payload["redirect"].(string)
		if redirect == "" {
			redirect = "/admin"
		}

		status := http.StatusUnauthorized
		resp := map[string]interface{}{"error": "Invalid MFA code", "code": "MFA_FAILED"}

		if guard.IsMFALocked(ctx, ip) {
			status = http.StatusTooManyRequests
			resp = map[string]interface{}{
				"error":   "MFA verification locked",
				"code":    "MFA_LOCKED",
				"message": "Too many invalid MFA attempts. Try again in 10 minutes.",
			}
			payload["mfa_locked"] = true
		} else {
			code = strings.TrimSpace(code)
			if defense.ValidMFABackup(code) {
				guard.ClearAuthFails(ctx, ip)
				token, err := sessions.Create(ctx, ip, defense.RoleAdmin)
				if err != nil {
					status = http.StatusServiceUnavailable
					resp = map[string]interface{}{"error": "session unavailable", "code": "SESSION_ERROR"}
				} else {
					status = http.StatusOK
					resp = map[string]interface{}{"success": true, "redirect": redirect, "role": defense.RoleAdmin}
					defense.SetSessionCookie(w, token)
					http.SetCookie(w, &http.Cookie{
						Name: "acme_jwt", Value: issueFakeJWT(ip),
						Path: "/", MaxAge: 3600, HttpOnly: true,
						Secure: runtime.CookieSecure(), SameSite: http.SameSiteLaxMode,
					})
					payload["mfa_backup_used"] = true
				}
			} else {
				failCount, locked := guard.IncMFAFail(ctx, ip)
				payload["mfa_failures"] = failCount
				if locked {
					status = http.StatusTooManyRequests
					resp = map[string]interface{}{
						"error":   "MFA verification locked",
						"code":    "MFA_LOCKED",
						"message": "Too many invalid MFA attempts. Try again in 10 minutes.",
					}
				}
			}
		}

		_ = logger.Log(ctx, events.Event{
			IP: ip, Method: r.Method, Endpoint: "/auth/mfa/verify",
			Payload: payload, UserAgent: r.UserAgent(), StatusCode: status,
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(resp)
	}
}

func handleRegister(logger *events.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := events.ClientIP(r)
		ctx := r.Context()
		payload := events.ReadBody(w, r, 4096)
		invite, _ := payload["invite_code"].(string)
		email, _ := payload["email"].(string)

		status := http.StatusForbidden
		resp := map[string]interface{}{
			"error":   "access denied",
			"code":    "ACCESS_DENIED",
			"message": "Invalid or expired invite code.",
		}

		if defense.ValidInvite(invite) {
			token, err := sessions.Create(ctx, ip, defense.RoleViewer)
			if err != nil {
				status = http.StatusServiceUnavailable
				resp = map[string]interface{}{"error": "session unavailable", "code": "SESSION_ERROR"}
			} else {
				status = http.StatusCreated
				resp = map[string]interface{}{
					"status":  "invite_accepted",
					"role":    defense.RoleViewer,
					"email":   email,
					"message": "Registration complete.",
					"scopes":  []string{"storage:read", "status:read"},
				}
				defense.SetSessionCookie(w, token)
				payload["registration_bypass"] = true
				payload["invite_accepted"] = true
			}
		} else if invite != "" {
			payload["invalid_invite"] = true
			resp["message"] = "Invalid or expired invite code."
		}

		_ = logger.Log(ctx, events.Event{
			IP: ip, Method: r.Method, Endpoint: "/auth/register",
			Payload: payload, UserAgent: r.UserAgent(), StatusCode: status,
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(resp)
	}
}

func handleForgotPassword(logger *events.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := events.ClientIP(r)
		payload := events.ReadBody(w, r, 4096)
		_ = logger.Log(r.Context(), events.Event{
			IP: ip, Method: r.Method, Endpoint: "/auth/forgot-password",
			Payload: payload, UserAgent: r.UserAgent(), StatusCode: 200,
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "If the account exists, a reset link has been sent.",
		})
	}
}

func handleToken(logger *events.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := events.ClientIP(r)
		payload := events.ReadBody(w, r, 4096)
		_ = logger.Log(r.Context(), events.Event{
			IP: ip, Method: r.Method, Endpoint: "/auth/token",
			Payload: payload, UserAgent: r.UserAgent(), StatusCode: 401,
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid grant"})
	}
}

func handleMFA(logger *events.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := events.ClientIP(r)
		payload := events.ReadBody(w, r, 4096)
		_ = logger.Log(r.Context(), events.Event{
			IP: ip, Method: r.Method, Endpoint: "/auth/mfa",
			Payload: payload, UserAgent: r.UserAgent(), StatusCode: 401,
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid MFA code", "code": "MFA_FAILED"})
	}
}

func handleOAuthCallback(logger *events.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := events.ClientIP(r)
		params := events.QueryParams(r)
		email, _ := params["email"].(string)
		clientID, _ := params["client_id"].(string)
		state, _ := params["state"].(string)
		status := http.StatusBadRequest
		resp := map[string]string{"error": "invalid OAuth state", "code": "OAUTH_STATE_MISMATCH"}

		if clientID == defense.OAuthClientID && email != "" && strings.Contains(email, "@") && state != "" {
			status = http.StatusOK
			resp = map[string]string{
				"status": "mfa_required",
				"next":   "/login/mfa",
			}
			params["oauth_client_verified"] = true
		} else if email != "" && strings.Contains(email, "@") {
			status = http.StatusForbidden
			resp = map[string]string{
				"error":   "unauthorized OAuth client",
				"code":    "OAUTH_CLIENT_UNKNOWN",
				"message": "Access denied.",
			}
		}
		_ = logger.Log(r.Context(), events.Event{
			IP: ip, Method: r.Method, Endpoint: "/auth/oauth/callback",
			Payload: params, UserAgent: r.UserAgent(), StatusCode: status,
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(resp)
	}
}

func handleSession(logger *events.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := events.ClientIP(r)
		role := defense.SessionRole(r)
		_ = logger.Log(r.Context(), events.Event{
			IP: ip, Method: r.Method, Endpoint: "/auth/session",
			Payload: events.QueryParams(r), UserAgent: r.UserAgent(), StatusCode: 200,
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		jwt := ""
		if c, err := r.Cookie("acme_jwt"); err == nil {
			jwt = c.Value
		}
		user := ""
		if role == defense.RoleAdmin {
			user = "admin@acmecorp.com"
		} else if role == defense.RoleViewer {
			user = "contractor@acmecorp.com"
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": role != "",
			"role":          role,
			"user":          user,
			"session_id":    "sess_" + ip,
			"token_type":    "Bearer",
			"expires_in":    3600,
			"has_jwt":       jwt != "",
		})
	}
}

func handleLogout(logger *events.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := events.ClientIP(r)
		_ = logger.Log(r.Context(), events.Event{
			IP: ip, Method: r.Method, Endpoint: "/auth/logout",
			Payload: events.QueryParams(r), UserAgent: r.UserAgent(), StatusCode: 302,
		})
		if c, err := r.Cookie(sessionCookie); err == nil {
			sessions.Invalidate(r.Context(), c.Value)
		}
		defense.ClearSessionCookie(w)
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func handleAuthCatchAll(logger *events.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := events.ClientIP(r)
		_ = logger.Log(r.Context(), events.Event{
			IP: ip, Method: r.Method, Endpoint: r.URL.Path,
			Payload: events.QueryParams(r), UserAgent: r.UserAgent(), StatusCode: 404,
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	}
}

func issueFakeJWT(_ string) string {
	return "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbkBhY21lY29ycC5jb20iLCJyb2xlIjoiYWRtaW4ifQ." + defense.FakeJWTMarker
}