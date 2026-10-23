package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiskManifestMachineRouteAuthenticationAndStrictQuery(t *testing.T) {
	f := newJobsFixture(t, "example-device")
	endpoint := "/v1/ops-manifests/manifest-1?job_id=job-1&digest=sha256:" + strings.Repeat("a", 64)
	for _, token := range []string{"", "not-a-machine-credential"} {
		req := httptest.NewRequest("GET", endpoint, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		response := httptest.NewRecorder()
		f.mux.ServeHTTP(response, req)
		if response.Code != http.StatusUnauthorized {
			t.Fatal("machine auth bypass", response.Code)
		}
	}
	for _, query := range []string{"", "?job_id=job-1", "?job_id=job-1&digest=a&path=/tmp", "?job_id=a&job_id=b&digest=a"} {
		req := httptest.NewRequest("GET", "/v1/ops-manifests/manifest-1"+query, nil)
		req.Header.Set("Authorization", "Bearer "+f.machine.token)
		response := httptest.NewRecorder()
		f.mux.ServeHTTP(response, req)
		if response.Code != 400 {
			t.Fatal("strict query bypass", response.Code, response.Body.String())
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("private response cacheable")
		}
	}
	req := httptest.NewRequest("GET", endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+f.machine.token)
	response := httptest.NewRecorder()
	f.mux.ServeHTTP(response, req)
	if response.Code < 400 {
		t.Fatal("unassigned manifest fetched")
	}
}
func TestDiskManifestSigningKeyDefaultsAndPermissions(t *testing.T) {
	f := newJobsFixture(t, "example-device")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fixture-key.pem")
	raw := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err = os.WriteFile(path, raw, 0644); err != nil {
		t.Fatal(err)
	}
	if err = configureDiskManifestSigningKey(f.store, path); err == nil {
		t.Fatal("public private-key permissions accepted")
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err = configureDiskManifestSigningKey(f.store, path); err != nil {
		t.Fatal(err)
	}
	alias := path + ".link"
	if err = os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if err = configureDiskManifestSigningKey(f.store, alias); err == nil {
		t.Fatal("symlink key accepted")
	}
}
