package main

import (
	"fmt"
	"net/http"

	"github.com/honeypot/shared/defense"
	"github.com/honeypot/shared/events"
)

type fakeApp struct {
	Path string
	Trap string
	Name string
	HTML string
}

func fakeInternalApps() []fakeApp {
	apps := []struct{ path, trap, name, color, tagline string }{
		{"/jenkins", "jenkins_probe", "Jenkins", "#335061", "Build Server"},
		{"/jira", "jira_probe", "Jira", "#0052CC", "Project Tracking"},
		{"/confluence", "confluence_probe", "Confluence", "#172B4D", "Team Wiki"},
		{"/grafana", "grafana_probe", "Grafana", "#111217", "Metrics & Dashboards"},
	}
	out := make([]fakeApp, 0, len(apps))
	for _, a := range apps {
		out = append(out, fakeApp{
			Path: a.path,
			Trap: a.trap,
			Name: a.name,
			HTML: fmt.Sprintf(`<!DOCTYPE html><html><head><title>Sign in - %s</title>
<style>body{font-family:system-ui;background:%s;color:#fff;min-height:100vh;display:flex;align-items:center;justify-content:center;margin:0}
.card{background:#fff;color:#111;width:360px;padding:32px;border-radius:8px;box-shadow:0 8px 30px rgba(0,0,0,.25)}
h1{font-size:22px;margin:0 0 4px}p{color:#64748b;font-size:13px;margin:0 0 20px}
input{width:100%%;padding:10px;margin:8px 0 14px;border:1px solid #cbd5e1;border-radius:6px;box-sizing:border-box}
button{width:100%%;padding:11px;background:%s;color:#fff;border:none;border-radius:6px;font-weight:600;cursor:pointer}
.hint{font-size:11px;color:#94a3b8;margin-top:14px;text-align:center}</style></head>
<body><div class="card"><h1>%s</h1><p>%s - internal.acmecorp.com</p>
<form method="post"><label>Username</label><input name="username" autocomplete="username">
<label>Password</label><input name="password" type="password" autocomplete="current-password">
<button>Sign in</button></form>
<p class="hint">SSO available via <a href="/login/sso">AcmeCorp IdP</a></p></div></body></html>`,
				a.name, a.color, a.color, a.name, a.tagline),
		})
	}
	return out
}

func registerDeception(mux *http.ServeMux, logger *events.Logger) {
	for _, app := range fakeInternalApps() {
		a := app
		mux.HandleFunc(a.Path, handleFakeApp(logger, a))
		mux.HandleFunc(a.Path+"/login", handleFakeApp(logger, a))
	}
	mux.HandleFunc("/storage/", handleStorageBrowser(logger))
	mux.HandleFunc("/upload", handleUploadPage(logger))
	mux.HandleFunc("/upload/submit", handleUploadSubmit(logger))
	mux.HandleFunc("/error", handleErrorLeak(logger))
}

func requireSessionOrWAF(w http.ResponseWriter, r *http.Request, logger *events.Logger, endpoint, trap string) bool {
	if defense.HasViewerOrAdmin(r) {
		return true
	}
	ip := events.ClientIP(r)
	tier := guard.ResolveTrapTier(r.Context(), ip, trap, true, false)
	if tier == 0 {
		_ = logger.Log(r.Context(), events.Event{
			IP: ip, Method: r.Method, Endpoint: endpoint,
			Payload: map[string]interface{}{"trap": trap, "waf_blocked": true},
			UserAgent: r.UserAgent(), StatusCode: 403,
		})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-WAF-Rule", "internal-app-protection")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(defense.WAFBody))
		return false
	}
	_ = logger.Log(r.Context(), events.Event{
		IP: ip, Method: r.Method, Endpoint: endpoint,
		Payload: map[string]interface{}{"trap": trap, "reason": "no_session", "tier": tier},
		UserAgent: r.UserAgent(), StatusCode: 302,
	})
	http.Redirect(w, r, "/login?redirect="+endpoint, http.StatusFound)
	return false
}

func handleFakeApp(logger *events.Logger, app fakeApp) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireSessionOrWAF(w, r, logger, r.URL.Path, app.Trap) {
			return
		}
		payload := map[string]interface{}{"trap": app.Trap, "app": app.Name}
		if r.Method == http.MethodPost {
			payload = events.ReadBody(w, r, 8192)
			payload["trap"] = app.Trap
			payload["app"] = app.Name
		}
		_ = logger.Log(r.Context(), events.Event{
			IP: events.ClientIP(r), Method: r.Method, Endpoint: r.URL.Path,
			Payload: payload, UserAgent: r.UserAgent(), StatusCode: 200,
		})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodPost {
			w.Write([]byte(fmt.Sprintf("<html><body style='font-family:system-ui;padding:40px'><h1>%s</h1><p>Invalid credentials.</p><a href='%s'>Back</a></body></html>", app.Name, app.Path)))
			return
		}
		w.Write([]byte(app.HTML))
	}
}

const storageHTML = `<!DOCTYPE html><html><head><title>AcmeCorp Storage</title>
<style>body{font-family:system-ui;background:#0f172a;color:#e2e8f0;margin:0;padding:32px}
h1{font-size:20px}.bucket{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:16px;margin:12px 0}
a{color:#38bdf8;font-size:14px;display:block;margin:6px 0}</style></head><body>
<h1>Object Storage - acme-prod-bucket</h1>
<div class="bucket"><strong>acme-backups/</strong>
<a href="/downloads/exports/employee-export.csv">employee-export-2026.csv</a>
<a href="/downloads/exports/vpn-config.ovpn">vpn-config.ovpn</a>
<a href="/downloads/exports/api-keys-backup.json">api-keys-backup.json</a></div>
<div class="bucket"><strong>hr-confidential/</strong>
<a href="/downloads/exports/payroll-q2.xlsx">payroll-q2.xlsx (restricted)</a></div>
<p style="font-size:12px;color:#64748b">Region: us-east-1 | Versioning enabled</p></body></html>`

func handleStorageBrowser(logger *events.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireSessionOrWAF(w, r, logger, r.URL.Path, "storage_browser") {
			return
		}
		_ = logger.Log(r.Context(), events.Event{
			IP: events.ClientIP(r), Method: r.Method, Endpoint: r.URL.Path,
			Payload: map[string]interface{}{"trap": "storage_browser"},
			UserAgent: r.UserAgent(), StatusCode: 200,
		})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(storageHTML))
	}
}

const uploadHTML = `<!DOCTYPE html><html><head><title>Support Upload - AcmeCorp</title>
<style>body{font-family:system-ui;background:#f8fafc;min-height:100vh;display:flex;align-items:center;justify-content:center;margin:0}
.card{background:#fff;padding:32px;border-radius:12px;width:420px;box-shadow:0 4px 20px rgba(0,0,0,.08)}
input,textarea{width:100%%;padding:10px;margin:8px 0 14px;border:1px solid #cbd5e1;border-radius:8px;box-sizing:border-box}
button{width:100%%;padding:12px;background:#2563eb;color:#fff;border:none;border-radius:8px;cursor:pointer}
.ok{display:none;color:#166534;background:#dcfce7;padding:10px;border-radius:8px;font-size:14px}</style></head>
<body><div class="card"><h2>Submit a support attachment</h2>
<div class="ok" id="ok">Upload queued for malware scan - ticket #INC-88421</div>
<form id="f"><input name="email" placeholder="Work email"><input name="file" type="file">
<textarea name="notes" rows="3" placeholder="Describe the issue"></textarea>
<button type="submit">Upload</button></form></div>
<script>document.getElementById('f').onsubmit=async(e)=>{e.preventDefault();
const fd=new FormData(e.target);await fetch('/upload/submit',{method:'POST',body:JSON.stringify({email:fd.get('email'),file:fd.get('file')?.name,notes:fd.get('notes')}),headers:{'Content-Type':'application/json'}});
document.getElementById('ok').style.display='block'};</script></body></html>`

func handleUploadPage(logger *events.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Redirect(w, r, "/upload", http.StatusFound)
			return
		}
		_ = logger.Log(r.Context(), events.Event{
			IP: events.ClientIP(r), Method: r.Method, Endpoint: "/upload",
			Payload: events.QueryParams(r), UserAgent: r.UserAgent(), StatusCode: 200,
		})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(uploadHTML))
	}
}

func handleUploadSubmit(logger *events.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		payload := events.ReadBody(w, r, 65536)
		_ = logger.Log(r.Context(), events.Event{
			IP: events.ClientIP(r), Method: r.Method, Endpoint: "/upload/submit",
			Payload: payload, UserAgent: r.UserAgent(), StatusCode: 202,
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte(`{"status":"queued","scan":"pending","ticket":"INC-88421"}`))
	}
}

func handleErrorLeak(logger *events.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := events.ClientIP(r)
		code := r.URL.Query().Get("code")
		if code == "" {
			code = "500"
		}
		if !defense.HasSession(r) && guard.TotalProbes(r.Context(), ip) < 3 {
			_ = logger.Log(r.Context(), events.Event{
				IP: ip, Method: r.Method, Endpoint: "/error",
				Payload: map[string]interface{}{"trap": "error_leak", "waf_blocked": true},
				UserAgent: r.UserAgent(), StatusCode: 404,
			})
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`<!DOCTYPE html><html><body style="font-family:system-ui;padding:40px"><h1>404 Not Found</h1><p>The requested resource does not exist.</p></body></html>`))
			return
		}
		_ = logger.Log(r.Context(), events.Event{
			IP: ip, Method: r.Method, Endpoint: "/error",
			Payload: map[string]interface{}{"trap": "error_leak", "code": code},
			UserAgent: r.UserAgent(), StatusCode: 500,
		})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf(`<!DOCTYPE html><html><body style="font-family:monospace;padding:24px;background:#1e1e1e;color:#f87171">
<h1>Internal Server Error</h1><pre>Traceback (most recent call last):
  File "/app/api/handlers/billing.py", line 142, in process_invoice
    conn = psycopg2.connect("postgres://acme_app:%s@db.internal:5432/acme_prod")
psycopg2.OperationalError: connection refused - fallback host db-staging.internal.acmecorp.com
JWT_SECRET=%s
</pre><p style="color:#94a3b8;font-size:12px">Ref: ERR-%s | env=production</p></body></html>`, defense.DBPassword, defense.JWTSecret, code)))
	}
}