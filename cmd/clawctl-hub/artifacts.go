package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/teddashh/AI-Intune/internal/artifact"
	"github.com/teddashh/AI-Intune/internal/model"
)

func artifactsDirFor(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), "artifacts")
}

func cmdArtifact(argv []string) {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: clawctl-hub artifact fetch|list|show [flags]")
		os.Exit(2)
	}
	switch argv[0] {
	case "fetch":
		cmdArtifactFetch(argv[1:])
	case "list", "show":
		if err := runArtifactReadCommand(context.Background(), argv, os.Stdout, os.Stderr); err != nil &&
			!errors.Is(err, flag.ErrHelp) {
			log.Fatal(terminalSafe(err.Error()))
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: artifact %s (available: fetch, list, show)\n", argv[0])
		os.Exit(2)
	}
}

func cmdArtifactFetch(argv []string) {
	if err := runArtifactFetchCommand(context.Background(), argv, os.Stdout, os.Stderr); err != nil &&
		!errors.Is(err, flag.ErrHelp) {
		log.Fatal(terminalSafe(err.Error()))
	}
}

func (h *hub) handleGetArtifact(w http.ResponseWriter, r *http.Request, machineID string) {
	w.Header().Set("Cache-Control", "private, no-store")
	digest := r.PathValue("sha256")
	if !artifact.ValidSHA256Hex(digest) {
		writeErr(w, http.StatusNotFound, model.ErrArtifactNotFound, "artifact 不存在")
		return
	}
	allowed, err := h.store.MachineMayDownloadArtifact(machineID, digest)
	if err != nil {
		h.finishStoreError(w, "核對 artifact download grant", machineID, "核對 artifact download grant 失敗", err)
		return
	}
	if !allowed {
		// 不區分「bytes 不存在」與「這台沒有持有引用它的 active job」，避免
		// machine bearer token 把 content-addressed catalog 當列舉介面。
		writeErr(w, http.StatusNotFound, model.ErrArtifactNotFound, "artifact 不存在")
		return
	}
	// ⚠ 擋的是把 ../、編碼斜線或額外 path segment 變成任意檔案讀取：只有
	// 恰好 64 個小寫 hex 通過，路徑也只由 artifactsDir 與驗過的檔名組成。
	path := filepath.Join(h.artifactsDir, digest+".tgz")
	entry, err := os.Lstat(path)
	if err != nil || !entry.Mode().IsRegular() {
		if h.serveRemoteArtifact(w, r, digest) {
			return
		}
		writeErr(w, http.StatusNotFound, model.ErrArtifactNotFound, "artifact 不存在")
		return
	}
	f, err := os.Open(path)
	if err != nil {
		writeErr(w, http.StatusNotFound, model.ErrArtifactNotFound, "artifact 不存在")
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(entry, info) {
		writeErr(w, http.StatusNotFound, model.ErrArtifactNotFound, "artifact 不存在")
		return
	}
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	w.Header().Set("ETag", `"`+digest+`"`)
	w.Header().Set("Content-Type", "application/gzip")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	if _, err := io.Copy(w, f); err != nil {
		log.Printf("streaming artifact %s failed: %v", digest, err)
	}
}
