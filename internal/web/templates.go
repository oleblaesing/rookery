package web

import (
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"time"
)

//go:embed templates/*.gohtml
var templateFS embed.FS

// Set at build time via ldflags.
var AssetVersion string

var tmplFuncs = template.FuncMap{
	"assetURL": func(path string) string {
		if AssetVersion == "" {
			return path
		}
		return path + "?v=" + AssetVersion
	},
	"formatDatetime": func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.UTC().Format("2 Jan 2006, 15:04 UTC")
	},
	"formatBytes": func(n int64) string {
		const kb, mb = 1024, 1024 * 1024
		switch {
		case n < kb:
			return fmt.Sprintf("%d B", n)
		case n < mb:
			return fmt.Sprintf("%.1f KB", float64(n)/kb)
		default:
			return fmt.Sprintf("%.1f MB", float64(n)/mb)
		}
	},
}

func renderFragment(w http.ResponseWriter, name string, data any) {
	t, err := template.New(name).Funcs(tmplFuncs).ParseFS(templateFS, "templates/"+name)
	if err != nil {
		slog.Error("render fragment: parse", "name", name, "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		slog.Error("render fragment: execute", "name", name, "err", err)
	}
}

// baseTemplate is cloned per render. Go's html/template shares one namespace
// across a parse, so a {{define "title"}} in one page would otherwise overwrite
// another's; cloning the base and layering one page on top isolates each.
var baseTemplate *template.Template

func init() {
	var err error
	baseTemplate, err = template.New("base.gohtml").Funcs(tmplFuncs).ParseFS(templateFS, "templates/base.gohtml")
	if err != nil {
		panic("web: parse base template: " + err.Error())
	}
}

func renderTemplate(w http.ResponseWriter, name string, data any) {
	// Clone so this render doesn't mutate the shared base template.
	t, err := baseTemplate.Clone()
	if err != nil {
		slog.Error("render template: clone base", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	t, err = t.ParseFS(templateFS, "templates/"+name)
	if err != nil {
		slog.Error("render template: parse page", "name", name, "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if err := t.ExecuteTemplate(w, "base", data); err != nil {
		slog.Error("render template: execute", "name", name, "err", err) // headers already sent
	}
}
