package main

import (
	"embed"
	"net/http"
	"strings"
)

//go:embed templates/*.html
var templateFS embed.FS

func renderTemplate(name string, vars map[string]string) ([]byte, error) {
	raw, err := templateFS.ReadFile("templates/" + name)
	if err != nil {
		return nil, err
	}
	out := string(raw)
	for key, val := range vars {
		out = strings.ReplaceAll(out, "{{"+key+"}}", val)
	}
	return []byte(out), nil
}

func writeHTML(w http.ResponseWriter, name string, vars map[string]string) {
	body, err := renderTemplate(name, vars)
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}