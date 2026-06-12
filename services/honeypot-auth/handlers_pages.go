package main

import (
	"net/http"
	"strings"

	"github.com/honeypot/shared/events"
)

func tenantBranding(tenant string) string {
	switch strings.ToLower(tenant) {
	case "globex":
		return "Globex Corporation"
	case "initech":
		return "Initech"
	default:
		return "AcmeCorp"
	}
}

func handleLoginPage(logger *events.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		redirect := r.URL.Query().Get("redirect")
		if redirect == "" {
			redirect = "/admin"
		}
		tenant := r.URL.Query().Get("tenant")
		_ = logger.Log(r.Context(), events.Event{
			IP: events.ClientIP(r), Method: r.Method, Endpoint: "/login",
			Payload: map[string]interface{}{"redirect": redirect, "tenant": tenant},
			UserAgent: r.UserAgent(), StatusCode: 200,
		})
		writeHTML(w, "login.html", map[string]string{
			"REDIRECT":    redirect,
			"TENANT_NAME": tenantBranding(tenant),
		})
	}
}

func handleSSOPage(logger *events.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provider := r.URL.Query().Get("provider")
		if provider == "" {
			provider = "okta"
		}
		_ = logger.Log(r.Context(), events.Event{
			IP: events.ClientIP(r), Method: r.Method, Endpoint: "/login/sso",
			Payload: map[string]interface{}{"provider": provider, "query": events.QueryParams(r)},
			UserAgent: r.UserAgent(), StatusCode: 200,
		})
		writeHTML(w, "sso.html", map[string]string{"PROVIDER": htmlEscape(provider)})
	}
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func handleMFAPage(logger *events.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		redirect := r.URL.Query().Get("redirect")
		if redirect == "" {
			redirect = "/admin"
		}
		writeHTML(w, "mfa.html", map[string]string{"REDIRECT": redirect})
	}
}

func handleRegisterPage(logger *events.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = logger.Log(r.Context(), events.Event{
			IP: events.ClientIP(r), Method: r.Method, Endpoint: "/register",
			Payload: events.QueryParams(r), UserAgent: r.UserAgent(), StatusCode: 200,
		})
		writeHTML(w, "register.html", nil)
	}
}

func handleForgotPasswordPage(logger *events.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := events.ClientIP(r)
		_ = logger.Log(r.Context(), events.Event{
			IP: ip, Method: r.Method, Endpoint: "/forgot-password",
			Payload: events.QueryParams(r), UserAgent: r.UserAgent(), StatusCode: 200,
		})
		writeHTML(w, "forgot.html", nil)
	}
}