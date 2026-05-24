package web

import (
	"embed"
	"html/template"
	"log/slog"
	"net/http"
)

//go:embed templates/*.gohtml
var templateFS embed.FS

// AssetVersion is injected at build time via ldflags
// (-X rookery/internal/web.AssetVersion=<git-hash>) and appended as a
// cache-busting query string to static asset URLs via the assetURL template func.
var AssetVersion string

var tmplFuncs = template.FuncMap{
	"assetURL": func(path string) string {
		if AssetVersion == "" {
			return path
		}
		return path + "?v=" + AssetVersion
	},
}

// renderFragment parses and executes a standalone HTML fragment template (no
// base shell). Used for partial-page responses polled by partials.js.
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

// baseTemplate is the parsed base shell. It is cloned for each render so
// that page-specific {{define}} blocks (title, content, scripts) don't
// bleed across pages.
//
// Background: Go's html/template parses all files in a single call into one
// shared namespace. A {{define "title"}} in read.gohtml silently overwrites
// the one in login.gohtml. The fix is to parse base.gohtml once, then clone
// it and layer exactly one page template on top per render — giving each page
// its own isolated namespace while sharing the base shell.
var baseTemplate *template.Template

func init() {
	var err error
	baseTemplate, err = template.New("base.gohtml").Funcs(tmplFuncs).ParseFS(templateFS, "templates/base.gohtml")
	if err != nil {
		panic("web: parse base template: " + err.Error())
	}
}

// renderTemplate clones the base template, parses the named page template on
// top of it, and executes the result. Each call gets a fresh namespace so
// {{define}} blocks from different pages never collide.
func renderTemplate(w http.ResponseWriter, name string, data any) {
	// Clone the base so this render does not mutate the shared template.
	t, err := baseTemplate.Clone()
	if err != nil {
		slog.Error("render template: clone base", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Parse the page template into the cloned set.
	t, err = t.ParseFS(templateFS, "templates/"+name)
	if err != nil {
		slog.Error("render template: parse page", "name", name, "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Execute the base shell (which {{block}}s into the page's definitions).
	if err := t.ExecuteTemplate(w, "base", data); err != nil {
		slog.Error("render template: execute", "name", name, "err", err)
		// Headers already sent; client gets a truncated page.
	}
}
