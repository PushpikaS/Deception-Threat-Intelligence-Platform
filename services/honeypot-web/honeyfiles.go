package main

import (
	"net/http"

	"github.com/honeypot/shared/defense"
	"github.com/honeypot/shared/events"
)

type honeyFile struct {
	Path        string
	Filename    string
	ContentType string
	Body        string
}

func honeyFiles() []honeyFile {
	return []honeyFile{
		{
			Path: "/downloads/exports/employee-export.csv", Filename: "employee-export-2026.csv",
			ContentType: "text/csv",
			Body: "email,department,role\nadmin@acmecorp.com,Engineering,admin\nc.lee@acmecorp.com,Finance,admin\nj.smith@acmecorp.com,Marketing,editor\n",
		},
		{
			Path: "/downloads/exports/vpn-config.ovpn", Filename: "vpn-config.ovpn",
			ContentType: "application/x-openvpn-profile",
			Body: defense.VPNConfigBody(),
		},
		{
			Path: "/downloads/exports/api-keys-backup.json", Filename: "api-keys-backup.json",
			ContentType: "application/json",
			Body: defense.APIKeysBackupJSON(),
		},
	}
}

func registerLockedFiles(mux *http.ServeMux, logger *events.Logger) {
	mux.HandleFunc("/downloads/exports/payroll-q2.xlsx", handleLockedFile(logger, "payroll-q2.xlsx"))
}

func handleLockedFile(logger *events.Logger, filename string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := events.ClientIP(r)
		_ = logger.Log(r.Context(), events.Event{
			IP: ip, Method: r.Method, Endpoint: r.URL.Path,
			Payload: map[string]interface{}{"trap": "honeyfile_download", "file": filename, "locked": true},
			UserAgent: r.UserAgent(), StatusCode: 403,
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"forbidden","message":"Insufficient permissions for this object."}`))
	}
}

func registerHoneyfiles(mux *http.ServeMux, logger *events.Logger) {
	for _, f := range honeyFiles() {
		file := f
		mux.HandleFunc(file.Path, handleHoneyfile(logger, file))
	}
}

func handleHoneyfile(logger *events.Logger, file honeyFile) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := events.ClientIP(r)
		if !defense.HasViewerOrAdmin(r) {
			tier := guard.ResolveTrapTier(r.Context(), ip, "honeyfile_download", true, false)
			if tier == 0 {
				_ = logger.Log(r.Context(), events.Event{
					IP: ip, Method: r.Method, Endpoint: r.URL.Path,
					Payload: map[string]interface{}{"trap": "honeyfile_download", "file": file.Filename, "waf_blocked": true},
					UserAgent: r.UserAgent(), StatusCode: 403,
				})
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(defense.WAFBody))
				return
			}
			_ = logger.Log(r.Context(), events.Event{
				IP: ip, Method: r.Method, Endpoint: r.URL.Path,
				Payload: map[string]interface{}{"trap": "honeyfile_download", "file": file.Filename, "reason": "no_session"},
				UserAgent: r.UserAgent(), StatusCode: 401,
			})
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"authentication required","login":"/login"}`))
			return
		}
		_ = logger.Log(r.Context(), events.Event{
			IP: ip, Method: r.Method, Endpoint: r.URL.Path,
			Payload: map[string]interface{}{"trap": "honeyfile_download", "file": file.Filename},
			UserAgent: r.UserAgent(), StatusCode: 200,
		})
		w.Header().Set("Content-Type", file.ContentType)
		w.Header().Set("Content-Disposition", `attachment; filename="`+file.Filename+`"`)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(file.Body))
	}
}