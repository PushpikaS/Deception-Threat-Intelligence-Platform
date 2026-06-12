package main

import "github.com/honeypot/shared/defense"

// Scanner trap definitions — realistic bait responses for automated probes.

type trapDef struct {
	Path        string
	Trap        string
	ContentType string
	Body        string
	Sensitive   bool
}

func scannerTraps() []trapDef {
	return []trapDef{
		{Path: "/.env", Trap: "env_leak", ContentType: "text/plain", Sensitive: true, Body: defense.EnvLeakBody()},
		{Path: "/.git/HEAD", Trap: "git_exposure", ContentType: "text/plain", Sensitive: true, Body: "ref: refs/heads/main\n"},
		{Path: "/.git/config", Trap: "git_exposure", ContentType: "text/plain", Sensitive: true, Body: "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://git.acmecorp.internal/acme/platform.git\n"},
		{Path: "/backup.sql", Trap: "backup_leak", ContentType: "text/plain", Sensitive: true, Body: defense.BackupSQLBody()},
		{Path: "/robots.txt", Trap: "robots", ContentType: "text/plain", Body: "User-agent: *\nDisallow: /admin/\nDisallow: /.env\nDisallow: /backup.sql\nDisallow: /api/v1/internal/\n"},
		{Path: "/sitemap.xml", Trap: "sitemap", ContentType: "application/xml", Body: `<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>/login</loc></url><url><loc>/admin</loc></url><url><loc>/api/v1/docs</loc></url><url><loc>/api/v1/internal/debug</loc></url></urlset>`},
		{Path: "/.well-known/security.txt", Trap: "security_txt", ContentType: "text/plain", Body: "Contact: security@acmecorp.com\nPolicy: https://acmecorp.com/security\nHiring: https://acmecorp.com/careers\n"},
		{Path: "/actuator/health", Trap: "actuator_probe", ContentType: "application/json", Body: `{"status":"UP","components":{"db":{"status":"UP","details":{"database":"PostgreSQL","validationQuery":"SELECT 1"}},"redis":{"status":"UP"}}}`},
		{Path: "/actuator/env", Trap: "actuator_probe", ContentType: "application/json", Sensitive: true, Body: defense.ActuatorEnvBody()},
		{Path: "/swagger.json", Trap: "swagger_probe", ContentType: "application/json", Body: `{"swagger":"2.0","info":{"title":"AcmeCorp Internal API","version":"3.2.1"},"paths":{"/api/v1/internal/debug":{"get":{"summary":"Debug diagnostics"}},"/api/v1/admin/export":{"get":{"summary":"Bulk export"}}}}`},
		{Path: "/server-status", Trap: "apache_status", ContentType: "text/plain", Body: "Server Version: Apache/2.4.58\nCurrent Requests: 14\nTotal Accesses: 2847193\n"},
		{Path: "/config.json", Trap: "config_leak", ContentType: "application/json", Sensitive: true, Body: defense.ConfigJSONBody()},
		{Path: "/debug/pprof/", Trap: "pprof_probe", ContentType: "text/html", Sensitive: true, Body: "<html><body><h1>/debug/pprof/</h1><ul><li><a href='heap'>heap</a></li><li><a href='goroutine'>goroutine</a></li></ul></body></html>"},
		{Path: "/.aws/credentials", Trap: "env_leak", ContentType: "text/plain", Sensitive: true, Body: defense.AWSCredentialsBody()},
		{Path: "/docker-compose.yml", Trap: "config_leak", ContentType: "text/plain", Sensitive: true, Body: defense.DockerComposeBody()},
		{Path: "/terraform.tfstate", Trap: "backup_leak", ContentType: "application/json", Sensitive: true, Body: defense.TerraformStateBody()},
		{Path: "/package.json", Trap: "config_leak", ContentType: "application/json", Body: `{"name":"acme-platform","scripts":{"start":"node server.js"},"dependencies":{"express":"^4.19.0"},"_deploy":{"registry":"npm.pkg.github.com/acme"}}`},
	}
}

const statusPageHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AcmeCorp Status</title>
<style>
*{box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:32px 20px 48px}
.wrap{max-width:720px;margin:0 auto}.hdr{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:8px}
h1{font-size:26px;font-weight:700;margin:0}.badge{font-size:11px;font-weight:600;padding:4px 10px;border-radius:999px;background:#14532d;color:#86efac}
.sub{color:#94a3b8;font-size:14px;margin:0 0 28px}.svc{display:flex;justify-content:space-between;align-items:center;padding:16px 0;border-bottom:1px solid #334155}
.svc span:first-child{font-weight:500}.ok{color:#86efac}.warn{color:#fcd34d}.down{color:#fca5a5}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:28px}
@media(max-width:560px){.grid{grid-template-columns:1fr}}
.card{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:16px}
.card h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:#94a3b8;margin:0 0 10px}
.card p,.card li{font-size:13px;color:#cbd5e1;line-height:1.5;margin:0}
.card ul{margin:8px 0 0;padding-left:18px}
.card a{color:#38bdf8;text-decoration:none}.card a:hover{text-decoration:underline}
.foot{margin-top:32px;padding-top:20px;border-top:1px solid #334155;font-size:12px;color:#64748b;line-height:1.6}
</style></head>
<body><div class="wrap">
<div class="hdr"><h1>AcmeCorp System Status</h1><span class="badge">All systems operational</span></div>
<p class="sub">Production | us-east-1 | Last updated <time id="ts"></time></p>
<div class="svc"><span>Employee Authentication (SSO)</span><span class="ok">Operational</span></div>
<div class="svc"><span>Admin Console</span><span class="ok">Operational</span></div>
<div class="svc"><span>REST API Gateway</span><span class="ok">Operational</span></div>
<div class="svc"><span>Object Storage</span><span class="ok">Operational</span></div>
<div class="svc"><span>Payment Processor</span><span class="warn">Degraded Performance</span></div>
<div class="svc"><span>Legacy WordPress (marketing)</span><span class="warn">Maintenance Window</span></div>
<div class="grid">
<div class="card"><h2>Public endpoints</h2><ul>
<li><a href="/login">Employee sign-in</a></li>
<li><a href="/login/sso?provider=okta">SSO portal (Okta)</a></li>
<li><a href="/api/v1/docs">API documentation</a></li>
<li><a href="/robots.txt">Crawler policy</a></li>
</ul></div>
<div class="card"><h2>Security &amp; compliance</h2><ul>
<li><a href="/.well-known/security.txt">security.txt</a></li>
<li><a href="/sitemap.xml">Site map</a></li>
<li><a href="/login?redirect=/admin/logs">Audit logs</a> (employee sign-in required)</li>
<li>Report incidents: security@acmecorp.com</li>
</ul></div>
</div>
<p class="foot">AcmeCorp internal status page | Not for public distribution.<br>
For access requests, contact HR at hr-access@acmecorp.com.</p>
</div>
<script>document.getElementById('ts').textContent=new Date().toUTCString()</script>
</body></html>`

const wordpressLoginHTML = `<!DOCTYPE html>
<html><head><title>Log In - WordPress</title>
<style>body{font-family:-apple-system,sans-serif;background:#f0f0f1;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
#loginform{background:#fff;padding:26px;width:320px;box-shadow:0 1px 3px rgba(0,0,0,.13)}
input{width:100%;padding:8px;margin:8px 0 16px;border:1px solid #8c8f94}
.button{background:#2271b1;color:#fff;border:none;padding:10px 16px;width:100%;cursor:pointer}</style></head>
<body><form id="loginform" action="/wp-admin/login.php" method="post">
<h1>Powered by WordPress</h1>
<label>Username</label><input name="log" autocomplete="username">
<label>Password</label><input name="pwd" type="password" autocomplete="current-password">
<button class="button">Log In</button></form></body></html>`

const phpMyAdminHTML = `<!DOCTYPE html>
<html><head><title>phpMyAdmin</title>
<style>body{font-family:Arial,sans-serif;background:#f5f5f5;margin:0}
.header{background:#235a81;color:#fff;padding:12px 20px}
.panel{max-width:480px;margin:60px auto;background:#fff;border:1px solid #aaa;padding:24px}
.err{color:#a00;font-size:13px;margin-bottom:12px}
input{width:100%;padding:8px;margin:6px 0 14px;border:1px solid #aaa}
button{background:#235a81;color:#fff;border:none;padding:10px 16px;cursor:pointer}</style></head>
<body><div class="header">phpMyAdmin 5.2.1</div>
<div class="panel"><div class="err">Cannot connect: invalid settings.</div>
<form action="/phpmyadmin/index.php" method="post">
<label>Server:</label><input name="pma_servername" value="db.internal.acmecorp.com">
<label>Username:</label><input name="pma_username" value="acme_admin">
<label>Password:</label><input name="pma_password" type="password">
<button>Go</button></form></div></body></html>`