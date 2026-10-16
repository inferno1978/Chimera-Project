package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

func TestSpa_ServesIndexForRoot(t *testing.T) {
	mockFS := fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<html>test</html>")},
	}

	handler := spa(mockFS)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("expected text/html, got %s", rec.Header().Get("Content-Type"))
	}
}

func TestSpa_ServesStaticFile(t *testing.T) {
	mockFS := fstest.MapFS{
		"index.html":     &fstest.MapFile{Data: []byte("<html>index</html>")},
		"assets/app.js":  &fstest.MapFile{Data: []byte("console.log('app')")},
		"assets/app.css": &fstest.MapFile{Data: []byte("body{}")},
	}

	handler := spa(mockFS)

	t.Run("serves js file", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("serves css file", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/assets/app.css", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}
	})
}

func TestSpa_FallbackToIndexForUnknownRoutes(t *testing.T) {
	mockFS := fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<html>spa</html>")},
	}

	handler := spa(mockFS)

	routes := []string{"/dashboard", "/settings/profile", "/unknown/deep/path"}
	for _, route := range routes {
		t.Run(route, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, route, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("expected 200 for %s, got %d", route, rec.Code)
			}
			if rec.Body.String() != "<html>spa</html>" {
				t.Errorf("expected index.html content for %s", route)
			}
		})
	}
}

func TestSpa_MissingIndex(t *testing.T) {
	mockFS := fstest.MapFS{} // empty fs

	handler := spa(mockFS)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when index.html missing, got %d", rec.Code)
	}
}

func TestRegisterSpa_NoUIBuild(t *testing.T) {
	mux := http.NewServeMux()
	emptyFS := fstest.MapFS{} // no ui/dist

	RegisterSpa(mux, emptyFS)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// fs.Sub succeeds but returns empty FS, spa() then fails to find index.html
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 (no index.html in empty sub-fs), got %d", rec.Code)
	}
}

func TestRegisterSpa_WithUIBuild(t *testing.T) {
	mux := http.NewServeMux()
	mockFS := fstest.MapFS{
		"ui/dist/index.html": &fstest.MapFile{Data: []byte("<html>app</html>")},
	}

	RegisterSpa(mux, mockFS)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}
