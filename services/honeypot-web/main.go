package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/honeypot/shared/defense"
	"github.com/honeypot/shared/events"
	"github.com/honeypot/shared/runtime"
)

var guard *defense.Guard

func main() {
	runtime.AssertProductionSafe()
	service := runtime.Env("SERVICE_NAME", "honeypot-web")
	port := runtime.Env("PORT", "8080")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	redisBundle, err := runtime.InitHoneypotRedis(ctx, service)
	if err != nil {
		log.Fatalf("init redis: %v", err)
	}
	defer redisBundle.Close()
	logger := redisBundle.Logger
	guard = defense.NewGuard(redisBundle.Defense)
	defense.SetSessionStore(defense.NewSessionStore(redisBundle.Defense))

	mux := http.NewServeMux()
	pages := adminPages()

	mux.HandleFunc("/admin/api/keys", handleAdminAPIKeys(logger))
	for id, page := range pages {
		p := page
		path := "/admin"
		if id != "dashboard" {
			path = "/admin/" + id
		}
		mux.HandleFunc(path, handleAdminPage(logger, p))
	}

	mux.HandleFunc("/static/", handleStatic(logger))
	registerDeception(mux, logger)
	registerHoneyfiles(mux, logger)
	registerLockedFiles(mux, logger)
	for _, trap := range scannerTraps() {
		t := trap
		mux.HandleFunc(t.Path, handleTrapDef(logger, t))
	}
	mux.HandleFunc("/wp-admin/", handleTrapHTML(logger, "wordpress_probe", "<html><body><p>WordPress admin area</p><a href='/wp-admin/login.php'>Log in</a></body></html>"))
	mux.HandleFunc("/wp-admin/login.php", handleWordPressLogin(logger))
	mux.HandleFunc("/phpmyadmin/", handleTrapHTML(logger, "phpmyadmin_probe", phpMyAdminHTML))
	mux.HandleFunc("/phpmyadmin/index.php", handlePhpMyAdminPost(logger))
	mux.HandleFunc("/status", handleStatusPage(logger))

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf(`{"status":"healthy","service":"%s"}`, service)))
	})

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
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

func handleAdminPage(logger *events.Logger, page adminPage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := events.ClientIP(r)
		if !defense.HasAdminSession(r) {
			_ = logger.Log(r.Context(), events.Event{
				IP: ip, Method: r.Method, Endpoint: r.URL.Path,
				Payload: map[string]interface{}{"reason": "no_session"},
				UserAgent: r.UserAgent(), StatusCode: 302,
			})
			http.Redirect(w, r, "/login?redirect="+r.URL.Path, http.StatusFound)
			return
		}
		_ = logger.Log(r.Context(), events.Event{
			IP: ip, Method: r.Method, Endpoint: r.URL.Path,
			Payload: map[string]interface{}{"page": page.ID, "query": events.QueryParams(r)},
			UserAgent: r.UserAgent(), StatusCode: 200,
		})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(renderAdmin(page)))
	}
}

func handleAdminAPIKeys(logger *events.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := events.ClientIP(r)
		if !defense.HasAdminSession(r) {
			_ = logger.Log(r.Context(), events.Event{
				IP: ip, Method: r.Method, Endpoint: "/admin/api/keys",
				Payload: map[string]interface{}{"reason": "no_session"},
				UserAgent: r.UserAgent(), StatusCode: 401,
			})
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"authentication required","login":"/login"}`))
			return
		}
		_ = logger.Log(r.Context(), events.Event{
			IP: ip, Method: r.Method, Endpoint: "/admin/api/keys",
			Payload: events.QueryParams(r), UserAgent: r.UserAgent(), StatusCode: 200,
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf(`{"keys":[{"name":"prod-deploy","prefix":"%s","created":"2026-01-15","scopes":["deploy","read"]}],"note":"rotate keys quarterly"}`, defense.HoneyAWSKey)))
	}
}

func handleStatic(logger *events.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Static assets are not logged — avoids duplicate profiles and noise
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(adminJS))
	}
}

func handleTrapDef(logger *events.Logger, trap trapDef) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := events.ClientIP(r)
		ctx := r.Context()
		session := defense.HasViewerOrAdmin(r)
		tier := guard.ResolveTrapTier(ctx, ip, trap.Trap, trap.Sensitive, session)

		payload := map[string]interface{}{
			"trap": trap.Trap, "query": events.QueryParams(r), "tier": tier,
		}
		status := http.StatusOK
		body := trap.Body
		ct := trap.ContentType

		switch tier {
		case 0:
			status = http.StatusForbidden
			payload["waf_blocked"] = true
			body = defense.WAFBody
			ct = "text/html; charset=utf-8"
			w.Header().Set("X-WAF-Rule", "sensitive-path-protection")
		case 1:
			body = defense.RedactSecrets(trap.Body)
		}

		_ = logger.Log(ctx, events.Event{
			IP: ip, Method: r.Method, Endpoint: r.URL.Path,
			Payload: payload, UserAgent: r.UserAgent(), StatusCode: status,
		})
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(status)
		w.Write([]byte(body))
	}
}

func handleStatusPage(logger *events.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = logger.Log(r.Context(), events.Event{
			IP: events.ClientIP(r), Method: r.Method, Endpoint: "/status",
			Payload: events.QueryParams(r), UserAgent: r.UserAgent(), StatusCode: 200,
		})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(statusPageHTML))
	}
}

func handleWordPressLogin(logger *events.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := events.ClientIP(r)
		payload := map[string]interface{}{"trap": "wordpress_login"}
		if r.Method == http.MethodPost {
			payload = events.ReadBody(w, r, 4096)
			payload["trap"] = "wordpress_login"
		}
		_ = logger.Log(r.Context(), events.Event{
			IP: ip, Method: r.Method, Endpoint: "/wp-admin/login.php",
			Payload: payload, UserAgent: r.UserAgent(), StatusCode: 200,
		})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodPost {
			w.Write([]byte("<html><body><h1>ERROR</h1><p>Invalid username or password.</p><a href='/wp-admin/login.php'>Try again</a></body></html>"))
			return
		}
		w.Write([]byte(wordpressLoginHTML))
	}
}

func handlePhpMyAdminPost(logger *events.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := events.ClientIP(r)
		payload := map[string]interface{}{"trap": "phpmyadmin_probe"}
		if r.Method == http.MethodPost {
			payload = events.ReadBody(w, r, 4096)
			payload["trap"] = "phpmyadmin_probe"
		}
		_ = logger.Log(r.Context(), events.Event{
			IP: ip, Method: r.Method, Endpoint: "/phpmyadmin/index.php",
			Payload: payload, UserAgent: r.UserAgent(), StatusCode: 200,
		})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(phpMyAdminHTML))
	}
}

func handleTrapHTML(logger *events.Logger, trap string, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := events.ClientIP(r)
		_ = logger.Log(r.Context(), events.Event{
			IP: ip, Method: r.Method, Endpoint: r.URL.Path,
			Payload: map[string]interface{}{"trap": trap},
			UserAgent: r.UserAgent(), StatusCode: 200,
		})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body))
	}
}

const adminJS = `function acmeToast(msg){const t=document.getElementById('toast');if(!t)return;t.textContent=msg;t.style.display='block';setTimeout(()=>t.style.display='none',2600)}
function acmeCopy(v){navigator.clipboard&&navigator.clipboard.writeText(v);acmeToast('Copied to clipboard')}
function acmeFilterTable(q){const rows=document.querySelectorAll('#users-table tbody tr');q=(q||'').toLowerCase();rows.forEach(r=>{r.style.display=r.innerText.toLowerCase().includes(q)?'':'none'})}
console.log('AcmeCorp Admin v2.4.1 loaded');`

