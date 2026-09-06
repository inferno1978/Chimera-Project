package handler

import (
	"io/fs"
	stdhttp "net/http"
	"path"
	"strings"
)

func RegisterSpa(mux *stdhttp.ServeMux, uiDist fs.FS) {
	dist, err := fs.Sub(uiDist, "ui/dist")
	if err == nil {
		mux.Handle("/", spa(dist))
	} else {
		mux.HandleFunc("/", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<html><head><title>B4</title></head><body>No UI build found</body></html>`))
		})
	}
}

func spa(fsys fs.FS) stdhttp.Handler {
	fileServer := stdhttp.FileServer(stdhttp.FS(fsys))
	return stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		upath := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if upath == "" {
			upath = "index.html"
		}
		f, err := fsys.Open(upath)
		if err == nil {
			if info, e := f.Stat(); e == nil && !info.IsDir() {
				_ = f.Close()
				fileServer.ServeHTTP(w, r)
				return
			}
			_ = f.Close()
		}
		data, err := fs.ReadFile(fsys, "index.html")
		if err != nil {
			w.WriteHeader(stdhttp.StatusInternalServerError)
			_, _ = w.Write([]byte("index.html not found"))
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(stdhttp.StatusOK)
		_, _ = w.Write(data)
	})
}
