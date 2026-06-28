package nvd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vul-dbgen/common"
)

func TestStreamVulnerabilities(t *testing.T) {
	payload := `{
		"resultsPerPage": 1,
		"startIndex": 0,
		"totalResults": 1,
		"format": "NVD_CVE",
		"version": "2.0",
		"vulnerabilities": [
			{
				"cve": {
					"id": "CVE-2026-0001",
					"published": "2026-01-02T03:04:05",
					"lastModified": "2026-01-03T03:04:05",
					"descriptions": [{"lang":"en","value":"desc"}],
					"metrics": {
						"cvssMetricV31": [{
							"cvssData": {
								"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
								"baseScore": 9.8,
								"baseSeverity": "CRITICAL"
							}
						}]
					},
					"configurations": [{
						"nodes": [{
							"operator": "OR",
							"cpeMatch": [{
								"vulnerable": true,
								"criteria": "cpe:2.3:a:test:test:*:*:*:*:*:*:*:*",
								"versionStartIncluding": "1.0",
								"versionEndExcluding": "2.0"
							}]
						}]
					}]
				}
			}
		]
	}`

	var got []NvdCve
	if err := streamVulnerabilities(strings.NewReader(payload), func(cve NvdCve) error {
		got = append(got, cve)
		return nil
	}); err != nil {
		t.Fatalf("streamVulnerabilities returned error: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(got))
	}

	// Setup SQLite database for testing
	tmpDir := t.TempDir()
	os.Setenv("NVD_TMP_PATH", tmpDir)
	defer os.Unsetenv("NVD_TMP_PATH")

	var fetcher NVDMetadataFetcher
	if err := fetcher.initDB(); err != nil {
		t.Fatalf("initDB failed: %v", err)
	}
	defer fetcher.Unload()

	if err := fetcher.prepareStatements(); err != nil {
		t.Fatalf("prepareStatements failed: %v", err)
	}

	if err := fetcher.beginBatch(); err != nil {
		t.Fatalf("beginBatch failed: %v", err)
	}

	if err := fetcher.storeMetadata(got[0]); err != nil {
		t.Fatalf("storeMetadata failed: %v", err)
	}

	if err := fetcher.commitBatch(); err != nil {
		t.Fatalf("commitBatch failed: %v", err)
	}

	// Query back the metadata
	meta, ok := fetcher.GetMetadata("CVE-2026-0001")
	if !ok {
		t.Fatalf("expected stored metadata")
	}
	if meta.Severity != common.Critical {
		t.Fatalf("expected critical severity, got %s", meta.Severity)
	}

	// Query version constraints
	affects, fixes, ok := fetcher.GetAffectedVersion("CVE-2026-0001")
	if !ok {
		t.Fatalf("expected version data")
	}
	if len(affects) == 0 {
		t.Fatalf("expected at least 1 affected version constraint")
	}
	if len(fixes) == 0 {
		t.Fatalf("expected at least 1 fixed version")
	}
}

func TestFindPreDownloadFilesPrefersMergedFeed(t *testing.T) {
	root := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() {
		_ = os.Chdir(oldWD)
	}()

	merged := filepath.Join(root, common.CVESourceRoot, "merged_nvd_feeds.json")
	if err := os.MkdirAll(filepath.Dir(merged), 0o755); err != nil {
		t.Fatalf("mkdir merged dir: %v", err)
	}
	if err := os.WriteFile(merged, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write merged feed: %v", err)
	}
	nvdDir := filepath.Join(root, common.CVESourceRoot, nvdSubfolder)
	if err := os.MkdirAll(nvdDir, 0o755); err != nil {
		t.Fatalf("mkdir nvd dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nvdDir, "nvdcve-2.0-2026.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write yearly feed: %v", err)
	}

	files, err := findPreDownloadFiles(nvdDir)
	if err != nil {
		t.Fatalf("findPreDownloadFiles returned error: %v", err)
	}
	expected := filepath.Join(common.CVESourceRoot, "merged_nvd_feeds.json")
	if len(files) != 1 || files[0] != expected {
		t.Fatalf("expected merged feed to be preferred, got %v", files)
	}
}
