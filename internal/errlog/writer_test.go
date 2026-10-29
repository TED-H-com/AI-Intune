package errlog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func readRecords(t *testing.T, path string) []Record {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var records []Record
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		records = append(records, r)
	}
	return records
}

func TestWriterCollapseConcurrentAndRedact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "errors.jsonl")
	w, err := NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := w.Write(Record{Component: "intune-agent", Code: "agent.job.failed", Msg: "failed token=supersecret", Context: map[string]any{"password": "bare-secret", "nested": []any{"Bearer abcdef"}}}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	records := readRecords(t, path)
	if len(records) != 1 || records[0].Count != 30 {
		t.Fatalf("records: %+v", records)
	}
	b, _ := os.ReadFile(path)
	for _, secret := range []string{"supersecret", "bare-secret", "abcdef"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("secret persisted: %s", secret)
		}
	}
	if records[0].Fingerprint != Fingerprint(records[0].Component, records[0].Code, records[0].Msg) {
		t.Fatal("wrong fingerprint")
	}
	if err := w.Write(Record{}); err == nil {
		t.Fatal("write after close succeeded")
	}
}

func TestWriterWindowFlush(t *testing.T) {
	path := filepath.Join(t.TempDir(), "errors.jsonl")
	w, err := NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	w.window = 10 * time.Millisecond
	r := Record{Component: "test", Code: "test.failed", Msg: "failed"}
	if err := w.Write(r); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		w.mu.Lock()
		empty := len(w.pending) == 0
		w.mu.Unlock()
		if empty {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("window did not flush")
		}
		time.Sleep(time.Millisecond)
	}
	if err := w.Write(r); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if records := readRecords(t, path); len(records) != 2 || records[0].Count != 1 || records[1].Count != 1 {
		t.Fatalf("records: %+v", records)
	}
}

func TestWriterRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "errors.jsonl")
	w, err := NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	w.max = 1
	for i := 0; i < 7; i++ {
		r := Record{Code: fmt.Sprintf("test.failure%d", i), Msg: "failure"}
		if err := w.Write(r); err != nil {
			t.Fatal(err)
		}
		w.mu.Lock()
		err = w.flush(Fingerprint(r.Component, r.Code, r.Msg))
		w.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		name := path
		if i > 0 {
			name = fmt.Sprintf("%s.%d", path, i)
		}
		records := readRecords(t, name)
		if len(records) != 1 || records[0].Code != fmt.Sprintf("test.failure%d", 6-i) {
			t.Fatalf("%s: %+v", name, records)
		}
	}
	if _, err := os.Stat(path + ".5"); !os.IsNotExist(err) {
		t.Fatalf("extra file: %v", err)
	}
}

func TestWriterIOFailure(t *testing.T) {
	w, err := NewWriter(filepath.Join(t.TempDir(), "errors.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(Record{Msg: "failed"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err == nil {
		t.Fatal("missing IO error")
	}
}
