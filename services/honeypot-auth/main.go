package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/honeypot/shared/defense"
	"github.com/honeypot/shared/runtime"
)

const sessionCookie = defense.SessionCookie

var (
	guard    *defense.Guard
	sessions *defense.SessionStore
)

func main() {
	runtime.AssertProductionSafe()
	service := runtime.Env("SERVICE_NAME", "honeypot-auth")
	port := runtime.Env("PORT", "8082")
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
	mux.HandleFunc("/login", handleLoginPage(logger))
	mux.HandleFunc("/login/mfa", handleMFAPage(logger))
	mux.HandleFunc("/login/sso", handleSSOPage(logger))
	mux.HandleFunc("/forgot-password", handleForgotPasswordPage(logger))
	mux.HandleFunc("/register", handleRegisterPage(logger))
	mux.HandleFunc("/auth/login", handleLogin(logger))
	mux.HandleFunc("/auth/ldap/bind", handleLDAPBind(logger))
	mux.HandleFunc("/auth/mfa/verify", handleMFAVerify(logger))
	mux.HandleFunc("/auth/register", handleRegister(logger))
	mux.HandleFunc("/auth/forgot-password", handleForgotPassword(logger))
	mux.HandleFunc("/auth/token", handleToken(logger))
	mux.HandleFunc("/auth/mfa", handleMFA(logger))
	mux.HandleFunc("/auth/oauth/callback", handleOAuthCallback(logger))
	mux.HandleFunc("/auth/session", handleSession(logger))
	mux.HandleFunc("/auth/logout", handleLogout(logger))
	mux.HandleFunc("/auth/", handleAuthCatchAll(logger))
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
		log.Printf("[%s] listening on :%s", service, port)
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