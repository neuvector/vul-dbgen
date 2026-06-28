package common

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	utils "github.com/vul-dbgen/share"
)

func TestCreateDBFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "cvedb.test")
	wantKey := KeyVersion{
		Version:    "1.2.3",
		UpdateTime: "2026-06-29T00:00:00Z",
		Keys: map[string]string{
			"ubuntu_full.tb": "key1",
		},
		Shas: map[string]string{
			"ubuntu_full.tb": "sha1",
			"apps.tb":        "sha2",
		},
	}
	wantFiles := []utils.TarFileInfo{
		{Name: "ubuntu_full.tb", Body: []byte("ubuntu-data")},
		{Name: "apps.tb", Body: []byte("apps-data")},
	}

	if err := CreateDBFile(&DBFile{
		Filename: out,
		Key:      wantKey,
		Files:    wantFiles,
	}); err != nil {
		t.Fatalf("CreateDBFile returned error: %v", err)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if len(raw) < 4 {
		t.Fatalf("expected db file to include 4-byte header length, got %d bytes", len(raw))
	}

	headerLen := binary.BigEndian.Uint32(raw[:4])
	if len(raw) < 4+int(headerLen) {
		t.Fatalf("header length %d exceeds file size %d", headerLen, len(raw))
	}

	var gotKey KeyVersion
	if err := json.Unmarshal(raw[4:4+headerLen], &gotKey); err != nil {
		t.Fatalf("failed to decode header json: %v", err)
	}
	if gotKey.Version != wantKey.Version || gotKey.UpdateTime != wantKey.UpdateTime {
		t.Fatalf("unexpected key header: %+v", gotKey)
	}
	if gotKey.Keys["ubuntu_full.tb"] != "key1" || gotKey.Shas["apps.tb"] != "sha2" {
		t.Fatalf("unexpected key maps: %+v", gotKey)
	}

	gzr, err := gzip.NewReader(bytes.NewReader(raw[4+headerLen:]))
	if err != nil {
		t.Fatalf("gzip.NewReader failed: %v", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	gotFiles := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar.Next failed: %v", err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("ReadAll(%s) failed: %v", hdr.Name, err)
		}
		gotFiles[hdr.Name] = string(body)
	}

	if len(gotFiles) != len(wantFiles) {
		t.Fatalf("expected %d tar entries, got %d", len(wantFiles), len(gotFiles))
	}
	for _, file := range wantFiles {
		if gotFiles[file.Name] != string(file.Body) {
			t.Fatalf("unexpected tar body for %s: %q", file.Name, gotFiles[file.Name])
		}
	}
}
