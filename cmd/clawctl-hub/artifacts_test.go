package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/store"
)

func TestServeArtifactRequiresAuthAndOnlyAcceptsLowercaseDigest(t *testing.T) {
	f := newJobsFixture(t, "machine-a")
	if err := os.MkdirAll(f.artifactsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte("stored tarball")
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(f.artifactsDir, digest+".tgz"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	grantArtifactDownload(t, f, digest, int64(len(body)))
	outsidePath := filepath.Join(filepath.Dir(f.artifactsDir), "outside-secret")
	outsideBody := []byte("must not leak")
	if err := os.WriteFile(outsidePath, outsideBody, 0o600); err != nil {
		t.Fatal(err)
	}
	outsideSum := sha256.Sum256(outsideBody)
	outsideDigest := hex.EncodeToString(outsideSum[:])
	if err := os.Symlink(outsidePath, filepath.Join(f.artifactsDir, outsideDigest+".tgz")); err != nil {
		t.Fatal(err)
	}

	get := requestArtifact(t, f.mux, http.MethodGet, "/v1/artifacts/"+digest, f.machine.token)
	if get.Code != http.StatusOK || !bytes.Equal(get.Body.Bytes(), body) {
		t.Fatalf("GET artifact = %d %q", get.Code, get.Body.Bytes())
	}
	if get.Header().Get("Content-Length") != fmt.Sprint(len(body)) ||
		get.Header().Get("ETag") != `"`+digest+`"` || get.Header().Get("Content-Type") != "application/gzip" {
		t.Fatalf("GET headers 不對：%v", get.Header())
	}
	head := requestArtifact(t, f.mux, http.MethodHead, "/v1/artifacts/"+digest, f.machine.token)
	if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("Content-Length") != fmt.Sprint(len(body)) ||
		head.Header().Get("ETag") != `"`+digest+`"` {
		t.Fatalf("HEAD 不對：status=%d headers=%v body=%q", head.Code, head.Header(), head.Body.Bytes())
	}
	unauthorized := requestArtifact(t, f.mux, http.MethodGet, "/v1/artifacts/"+digest, "")
	assertAPIError(t, unauthorized, http.StatusUnauthorized, model.ErrUnauthorized)
	other := enrollViaHTTP(t, f.mux, f.store, "machine-without-this-job")
	notGranted := requestArtifact(t, f.mux, http.MethodGet, "/v1/artifacts/"+digest, other.token)
	assertAPIError(t, notGranted, http.StatusNotFound, model.ErrArtifactNotFound)

	missing := requestArtifact(t, f.mux, http.MethodGet, "/v1/artifacts/"+strings.Repeat("0", 64), f.machine.token)
	assertAPIError(t, missing, http.StatusNotFound, model.ErrArtifactNotFound)
	symlink := requestArtifact(t, f.mux, http.MethodGet, "/v1/artifacts/"+outsideDigest, f.machine.token)
	assertAPIError(t, symlink, http.StatusNotFound, model.ErrArtifactNotFound)
	badPaths := []string{
		"/v1/artifacts/" + strings.Repeat("a", 63),
		"/v1/artifacts/" + strings.ToUpper(digest),
		"/v1/artifacts/..%2F..",
		"/v1/artifacts/..%2Foutside-secret",
		"/v1/artifacts/" + digest + "/outside-secret",
	}
	for _, path := range badPaths {
		rec := requestArtifact(t, f.mux, http.MethodGet, path, f.machine.token)
		if rec.Code != http.StatusNotFound {
			t.Errorf("不合法 path %q 回 %d，預期 404：%s", path, rec.Code, rec.Body.String())
		}
		if bytes.Contains(rec.Body.Bytes(), []byte("must not leak")) {
			t.Errorf("不合法 path %q 讀到 artifacts_dir 外內容", path)
		}
	}
}

func grantArtifactDownload(t *testing.T, f jobsFixture, digest string, size int64) {
	t.Helper()
	if _, err := f.store.DB().Exec(`UPDATE machine_registry SET channel='canary' WHERE machine_id=?`, f.machine.id); err != nil {
		t.Fatal(err)
	}
	spec := fmt.Sprintf(`{"kind":"openclaw","version":"2026.9.2","artifact":{"sha256":%q,"size":%d,"url":%q}}`,
		digest, size, "/v1/artifacts/"+digest)
	if _, _, err := f.store.CreateDeployment(store.NewDeployment{
		Channel: "canary", ResourceKind: "openclaw", ResourceID: "openclaw", Spec: spec,
		BatchSize: 1, CreatedBy: "test", Targets: []store.NewDeploymentTarget{{MachineID: f.machine.id, BatchNo: 1}},
		Job: store.NewJob{ArtifactDigest: "sha256:" + digest},
	}); err != nil {
		t.Fatal(err)
	}
}

func requestArtifact(t *testing.T, mux *http.ServeMux, method, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	mux.ServeHTTP(rec, req)
	return rec
}
