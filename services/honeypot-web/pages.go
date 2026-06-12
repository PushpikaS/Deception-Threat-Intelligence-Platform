package main

import (
	"fmt"
	"html"

	"github.com/honeypot/shared/defense"
)

type adminPage struct {
	ID    string
	Title string
	Body  string
}

func renderAdmin(page adminPage) string {
	active := func(id string) string {
		if id == page.ID {
			return ` class="active"`
		}
		return ""
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>%s - AcmeCorp Admin</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
.sidebar{width:240px;background:#1e293b;height:100vh;position:fixed;padding:24px 0;border-right:1px solid #334155}
.sidebar h2{padding:0 24px 24px;font-size:18px;color:#38bdf8;border-bottom:1px solid #334155}
.sidebar nav a{display:block;padding:12px 24px;color:#94a3b8;text-decoration:none;font-size:14px}
.sidebar nav a:hover,.sidebar nav a.active{background:#334155;color:#f1f5f9}
.sidebar .user{padding:16px 24px 0;font-size:12px;color:#64748b}
.sidebar .signout{display:block;padding:10px 24px 0;font-size:12px;color:#94a3b8;text-decoration:none}
.sidebar .signout:hover{color:#f87171}
.main{margin-left:240px;padding:32px}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:28px;gap:16px;flex-wrap:wrap}
.header h1{font-size:24px;font-weight:600}
.badge{background:#166534;color:#86efac;padding:4px 12px;border-radius:9999px;font-size:12px}
.btn{display:inline-block;padding:8px 14px;background:#2563eb;color:#fff;border-radius:8px;font-size:13px;text-decoration:none;border:none;cursor:pointer}
.btn.secondary{background:#334155;color:#e2e8f0}
.btn.danger{background:#991b1b}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:28px}
.card{background:#1e293b;border-radius:12px;padding:20px;border:1px solid #334155}
.card h3{font-size:12px;color:#64748b;margin-bottom:8px;text-transform:uppercase;letter-spacing:.05em}
.card .value{font-size:26px;font-weight:700;color:#f8fafc}
table{width:100%%;border-collapse:collapse;background:#1e293b;border-radius:12px;overflow:hidden;border:1px solid #334155}
th,td{padding:12px 16px;text-align:left;font-size:13px}
th{background:#334155;color:#94a3b8;font-weight:500;text-transform:uppercase;font-size:11px;letter-spacing:.05em}
tr{border-top:1px solid #334155}
.status{display:inline-block;width:8px;height:8px;border-radius:50%%;margin-right:8px}
.status.green{background:#22c55e}.status.yellow{background:#eab308}.status.red{background:#ef4444}
.pill{display:inline-block;padding:2px 8px;border-radius:9999px;font-size:11px;background:#334155;color:#cbd5e1}
.pill.admin{background:#1e3a5f;color:#7dd3fc}
.pill.warn{background:#422006;color:#fcd34d}
.toolbar{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap}
input,select,textarea{width:100%%;padding:10px 12px;border:1px solid #475569;border-radius:8px;background:#0f172a;color:#e2e8f0;font-size:13px}
label{display:block;font-size:12px;color:#94a3b8;margin-bottom:6px}
.field{margin-bottom:16px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:#93c5fd}
.note{font-size:12px;color:#64748b;margin-top:8px}
.toast{position:fixed;bottom:24px;right:24px;background:#14532d;color:#bbf7d0;padding:12px 16px;border-radius:8px;display:none;font-size:13px}
</style>
</head>
<body>
<div class="sidebar">
<h2>AcmeCorp Admin</h2>
<nav>
<a href="/admin"%s>Dashboard</a>
<a href="/admin/users"%s>Users</a>
<a href="/admin/settings"%s>Settings</a>
<a href="/admin/logs"%s>Audit Logs</a>
<a href="/admin/billing"%s>Billing</a>
<a href="/admin/api-keys"%s>API Keys</a>
<a href="/admin/security"%s>Security</a>
<a href="/admin/integrations"%s>Integrations</a>
</nav>
<div class="user">Signed in as admin@acmecorp.com</div>
<a href="/auth/logout" class="signout">Sign out</a>
</div>
<div class="main">
<div class="header">
<h1>%s</h1>
<span class="badge">Production | us-east-1</span>
</div>
%s
</div>
<div class="toast" id="toast"></div>
<script src="/static/admin.js"></script>
</body>
</html>`, html.EscapeString(page.Title), active("dashboard"), active("users"), active("settings"), active("logs"), active("billing"), active("api-keys"), active("security"), active("integrations"), html.EscapeString(page.Title), page.Body)
}

func pageDashboard() adminPage {
	return adminPage{
		ID: "dashboard", Title: "System Dashboard",
		Body: `
<div class="cards">
<div class="card"><h3>Active Users</h3><div class="value">1,284</div></div>
<div class="card"><h3>Revenue (MTD)</h3><div class="value">$48,291</div></div>
<div class="card"><h3>API Requests</h3><div class="value">2.4M</div></div>
<div class="card"><h3>Failed Logins (24h)</h3><div class="value">37</div></div>
</div>
<table>
<thead><tr><th>Service</th><th>Status</th><th>Latency</th><th>Region</th><th>Version</th></tr></thead>
<tbody>
<tr><td>api-gateway</td><td><span class="status green"></span>Healthy</td><td>12ms</td><td>us-east-1</td><td>3.2.1</td></tr>
<tr><td>auth-service</td><td><span class="status green"></span>Healthy</td><td>8ms</td><td>us-east-1</td><td>2.8.0</td></tr>
<tr><td>payment-processor</td><td><span class="status yellow"></span>Degraded</td><td>340ms</td><td>eu-west-1</td><td>1.14.2</td></tr>
<tr><td>notification-svc</td><td><span class="status green"></span>Healthy</td><td>22ms</td><td>us-west-2</td><td>4.0.1</td></tr>
</tbody>
</table>
<p class="note">Last deployment: 2026-06-02 03:14 UTC by deploy-bot</p>`,
	}
}

func pageUsers() adminPage {
	return adminPage{
		ID: "users", Title: "User Management",
		Body: `
<div class="toolbar">
<input type="search" placeholder="Search users by email or role…" style="max-width:320px" oninput="window.acmeFilterTable && acmeFilterTable(this.value)">
<button class="btn" onclick="acmeToast('Invite sent to pending approval queue')">Invite User</button>
</div>
<table id="users-table">
<thead><tr><th>Email</th><th>Role</th><th>Department</th><th>Last Login</th><th>Status</th><th></th></tr></thead>
<tbody>
<tr><td>admin@acmecorp.com</td><td><span class="pill admin">admin</span></td><td>Engineering</td><td>2 min ago</td><td>Active</td><td><button class="btn secondary" onclick="acmeToast('User record locked for review')">Edit</button></td></tr>
<tr><td>j.smith@acmecorp.com</td><td><span class="pill">editor</span></td><td>Marketing</td><td>3h ago</td><td>Active</td><td><button class="btn secondary">Edit</button></td></tr>
<tr><td>c.lee@acmecorp.com</td><td><span class="pill admin">admin</span></td><td>Finance</td><td>Yesterday</td><td>Active</td><td><button class="btn secondary">Edit</button></td></tr>
<tr><td>contractor-ext@partner.io</td><td><span class="pill warn">viewer</span></td><td>External</td><td>Never</td><td>Pending</td><td><button class="btn secondary">Edit</button></td></tr>
</tbody>
</table>`,
	}
}

func pageSettings() adminPage {
	return adminPage{
		ID: "settings", Title: "Organization Settings",
		Body: fmt.Sprintf(`
<div class="grid2">
<div>
<div class="field"><label>Organization name</label><input value="AcmeCorp International"></div>
<div class="field"><label>Primary domain</label><input value="acmecorp.com"></div>
<div class="field"><label>Session timeout (minutes)</label><input value="30"></div>
<div class="field"><label>Allowed SSO providers</label><input value="Okta, Azure AD, Google Workspace"></div>
</div>
<div>
<div class="field"><label>Webhook signing secret</label><input class="mono" value="%s"></div>
<div class="field"><label>Legacy API key (rotate Q3)</label><input class="mono" value="%s"></div>
<div class="field"><label>AWS deploy role ARN</label><input class="mono" value="%s"></div>
<div class="field"><label>Internal notes</label><textarea rows="4">Rotate legacy API keys before Q3 audit.</textarea></div>
</div>
</div>
<div class="toolbar"><button class="btn" onclick="acmeToast('Settings saved (staging sync queued)')">Save Changes</button></div>`,
			defense.WebhookSecret, defense.HoneyAPIKey, defense.DeployRoleARN),
	}
}

func pageLogs() adminPage {
	return adminPage{
		ID: "logs", Title: "Audit Logs",
		Body: `
<div class="toolbar">
<select style="max-width:200px"><option>All events</option><option>Auth failures</option><option>Admin changes</option><option>API key access</option></select>
<input type="search" placeholder="Filter by IP or user…" style="max-width:280px">
</div>
<table>
<thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>IP</th><th>Detail</th></tr></thead>
<tbody>
<tr><td>2026-06-09 14:22:01</td><td>admin@acmecorp.com</td><td>LOGIN_SUCCESS</td><td>10.0.4.12</td><td>MFA verified</td></tr>
<tr><td>2026-06-09 14:18:44</td><td>unknown</td><td>LOGIN_FAILED</td><td>203.0.113.8</td><td>Invalid password</td></tr>
<tr><td>2026-06-09 13:55:10</td><td>api-deploy</td><td>KEY_VIEWED</td><td>10.0.2.5</td><td>prod-deploy key accessed</td></tr>
<tr><td>2026-06-09 12:01:33</td><td>j.smith@acmecorp.com</td><td>SETTINGS_UPDATE</td><td>10.0.4.88</td><td>Webhook URL changed</td></tr>
</tbody>
</table>`,
	}
}

func pageBilling() adminPage {
	return adminPage{
		ID: "billing", Title: "Billing & Invoices",
		Body: `
<div class="cards">
<div class="card"><h3>Current Plan</h3><div class="value" style="font-size:18px">Enterprise</div></div>
<div class="card"><h3>Next Invoice</h3><div class="value" style="font-size:18px">Jul 1</div></div>
<div class="card"><h3>Card on File</h3><div class="value" style="font-size:18px">•••• 4242</div></div>
</div>
<table>
<thead><tr><th>Invoice</th><th>Amount</th><th>Status</th><th>Due</th><th></th></tr></thead>
<tbody>
<tr><td>INV-2026-006</td><td>$12,500.00</td><td><span class="pill">open</span></td><td>2026-07-01</td><td><button class="btn secondary">Download PDF</button></td></tr>
<tr><td>INV-2026-005</td><td>$12,500.00</td><td>Paid</td><td>2026-06-01</td><td><button class="btn secondary">Download PDF</button></td></tr>
<tr><td>INV-2026-004</td><td>$11,800.00</td><td>Paid</td><td>2026-05-01</td><td><button class="btn secondary">Download PDF</button></td></tr>
</tbody>
</table>
<p class="note">Stripe customer: cus_AcmeFakeStripeId001 | Billing contact: finance@acmecorp.com</p>`,
	}
}

func pageAPIKeys() adminPage {
	return adminPage{
		ID: "api-keys", Title: "API Keys",
		Body: fmt.Sprintf(`
<div class="toolbar">
<button class="btn" onclick="acmeToast('New key created - copy now, shown once')">Create API Key</button>
</div>
<table>
<thead><tr><th>Name</th><th>Key</th><th>Created</th><th>Last Used</th><th>Scopes</th><th></th></tr></thead>
<tbody>
<tr><td>prod-deploy</td><td class="mono">%s</td><td>2026-01-15</td><td>Today</td><td>deploy,read</td><td><button class="btn secondary" onclick="acmeCopy('%s')">Copy</button></td></tr>
<tr><td>billing-sync</td><td class="mono">%s</td><td>2025-11-02</td><td>Yesterday</td><td>billing</td><td><button class="btn secondary" onclick="acmeCopy('%s')">Copy</button></td></tr>
<tr><td>ci-readonly</td><td class="mono">%s</td><td>2026-03-20</td><td>3d ago</td><td>read</td><td><button class="btn danger" onclick="acmeToast('Revoke queued')">Revoke</button></td></tr>
</tbody>
</table>`,
			defense.HoneyAWSKey, defense.HoneyAWSKey,
			defense.HoneyStripeKey, defense.HoneyStripeKey,
			defense.HoneyAPIKey),
	}
}

func pageSecurity() adminPage {
	return adminPage{
		ID: "security", Title: "Security Posture",
		Body: `
<div class="cards">
<div class="card"><h3>MFA adoption</h3><div class="value">94%</div></div>
<div class="card"><h3>Failed logins (24h)</h3><div class="value">37</div></div>
<div class="card"><h3>Locked accounts</h3><div class="value">2</div></div>
</div>
<table>
<thead><tr><th>Control</th><th>Status</th><th>Owner</th><th>Last review</th></tr></thead>
<tbody>
<tr><td>SSO enforcement</td><td><span class="pill admin">Enabled</span></td><td>IT Security</td><td>2026-05-28</td></tr>
<tr><td>Session timeout</td><td><span class="pill">30 min</span></td><td>Platform</td><td>2026-04-12</td></tr>
<tr><td>API key rotation</td><td><span class="pill warn">Due Q3</span></td><td>Engineering</td><td>2026-01-15</td></tr>
</tbody>
</table>`,
	}
}

func pageIntegrations() adminPage {
	return adminPage{
		ID: "integrations", Title: "Integrations",
		Body: `
<table>
<thead><tr><th>Integration</th><th>Status</th><th>Endpoint</th><th></th></tr></thead>
<tbody>
<tr><td>Okta SSO</td><td>Connected</td><td class="mono">https://acmecorp.okta.com</td><td><button class="btn secondary">Configure</button></td></tr>
<tr><td>Stripe Billing</td><td>Connected</td><td class="mono">api.stripe.com</td><td><button class="btn secondary">Configure</button></td></tr>
<tr><td>Slack Alerts</td><td>Paused</td><td class="mono">hooks.slack.com/…</td><td><button class="btn secondary">Enable</button></td></tr>
</tbody>
</table>
<p class="note">Webhook deliveries require admin approval for new endpoints.</p>`,
	}
}

func adminPages() map[string]adminPage {
	return map[string]adminPage{
		"dashboard": pageDashboard(),
		"users":     pageUsers(),
		"settings":  pageSettings(),
		"logs":      pageLogs(),
		"billing":   pageBilling(),
		"api-keys":     pageAPIKeys(),
		"security":     pageSecurity(),
		"integrations": pageIntegrations(),
	}
}

