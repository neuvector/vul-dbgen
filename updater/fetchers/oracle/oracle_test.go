package oracle

import (
	"strings"
	"testing"

	"github.com/vul-dbgen/common"
)

func TestParseELSASkipsHTMLResponse(t *testing.T) {
	html := `
<!DOCTYPE html>
<html>
<body>
<hr>
</body>
</html>`

	vuls, err := parseELSA("com.oracle.elsa-20269999.xml", strings.NewReader(html))
	if err != nil {
		t.Fatalf("expected HTML response to be skipped without error, got: %v", err)
	}
	if len(vuls) != 0 {
		t.Fatalf("expected no vulnerabilities for skipped HTML response, got: %d", len(vuls))
	}
}

func TestListFeedFiles(t *testing.T) {
	indexHTML := `
<tr><td><a href="com.oracle.elsa-all.xml.bz2">com.oracle.elsa-all...&gt;</a></td></tr>
<tr><td><a href="com.oracle.elsa-ol6.xml.bz2">com.oracle.elsa-ol6...&gt;</a></td></tr>
<tr><td><a href="com.oracle.elsa-ol7.xml.bz2">com.oracle.elsa-ol7...&gt;</a></td></tr>
<tr><td><a href="com.oracle.elsa-ol8.xml.bz2">com.oracle.elsa-ol8...&gt;</a></td></tr>
<tr><td><a href="com.oracle.elsa-ol9.xml.bz2">com.oracle.elsa-ol9...&gt;</a></td></tr>
<tr><td><a href="com.oracle.elsa-ol10.xml.bz2">com.oracle.elsa-ol10...&gt;</a></td></tr>
<tr><td><a href="com.oracle.elsa-2026.xml.bz2">com.oracle.elsa-2026...&gt;</a></td></tr>`

	files := listFeedFiles([]byte(indexHTML))
	expected := []string{
		"com.oracle.elsa-all.xml.bz2",
		"com.oracle.elsa-ol10.xml.bz2",
		"com.oracle.elsa-ol6.xml.bz2",
		"com.oracle.elsa-ol7.xml.bz2",
		"com.oracle.elsa-ol8.xml.bz2",
		"com.oracle.elsa-ol9.xml.bz2",
	}

	if len(files) != len(expected) {
		t.Fatalf("expected %d files, got %d: %v", len(expected), len(files), files)
	}
	for i := range expected {
		if files[i] != expected[i] {
			t.Fatalf("expected file %d to be %q, got %q", i, expected[i], files[i])
		}
	}
}

func TestMergeVulnerabilityDeduplicatesFixedInAndCVEs(t *testing.T) {
	vulnMap := make(map[string]common.Vulnerability)
	version, err := common.NewVersion("1.1.1k-1")
	if err != nil {
		t.Fatalf("failed to parse test version: %v", err)
	}
	fixedIn := common.FeatureVersion{
		Feature: common.Feature{
			Name:      "openssl",
			Namespace: "oracle:9",
		},
		Version: version,
	}
	v := common.Vulnerability{
		Name:    "ELSA-2026-0001",
		FixedIn: []common.FeatureVersion{fixedIn},
		CVEs:    []common.CVE{{Name: "CVE-2026-0001"}},
	}

	mergeVulnerability(vulnMap, v)
	mergeVulnerability(vulnMap, v)

	got := vulnMap[v.Name]
	if len(got.FixedIn) != 1 {
		t.Fatalf("expected one fixed-in entry after dedupe, got %d", len(got.FixedIn))
	}
	if len(got.CVEs) != 1 {
		t.Fatalf("expected one CVE after dedupe, got %d", len(got.CVEs))
	}
}
