package apps

import (
	"testing"

	"reflect"

	"github.com/vul-dbgen/common"
)

// The logic to convert from patched version to affected version is not correct.
// In scanning, ruby affected version is ignored.
func TestRubyAffectedVersion(t *testing.T) {
	patched := [][]string{
		// []string{">= 2.12.5, < 3.0.0", ">= 3.7.2, < 4.0.0", ">= 4.0.0.beta8"},
		// 3-segment: prefix = drop last segment (unchanged behaviour)
		[]string{">= 1.3.1", "~> 1.2.2", "~> 1.1.1", "~> 1.0.4"},
		// 4-segment: prefix must be 3 segments, not 2 (NVSHAS-10357)
		[]string{"~> 4.0.3.1", "~> 4.0.4.1", "~> 6.0.1.1", ">= 6.0.4"},
		// uri CVE-2023-28755
		[]string{"~> 0.10.0.1", "~> 0.10.2", "~> 0.11.1", ">= 0.12.1"},
	}
	affected := [][]common.AppModuleVersion{
		// []ModuleVersion{{"lt", "2.12.5"}, {"gteq", "3.0.0"}, {"andlt", "3.7.2"}, {"gteq", "4.0.0"}, {"andlt", "4.0.0.beta8"}},
		[]common.AppModuleVersion{{"lt", "1.3.1"}, {"orlt", "1.2.2,1.2"}, {"orlt", "1.1.1,1.1"}, {"orlt", "1.0.4,1.0"}},
		[]common.AppModuleVersion{{"lt", "4.0.3.1,4.0.3"}, {"orlt", "4.0.4.1,4.0.4"}, {"orlt", "6.0.1.1,6.0.1"}, {"orlt", "6.0.4"}},
		[]common.AppModuleVersion{{"lt", "0.10.0.1,0.10.0"}, {"orlt", "0.10.2,0.10"}, {"orlt", "0.11.1,0.11"}, {"orlt", "0.12.1"}},
	}

	for i, c := range patched {
		mvs := generateAffectedVer(c)
		if !reflect.DeepEqual(mvs, affected[i]) {
			t.Errorf("Error parsing affected version: i=%d", i)
			t.Errorf("    expected: %s", affected[i])
			t.Errorf("    actual:   %s", mvs)
		}
	}
}

func TestNginxVulnerabilityWithoutSeverity(t *testing.T) {
	originalVulMap := vulMap
	vulMap = make(map[string]*common.AppModuleVul)
	t.Cleanup(func() { vulMap = originalVulMap })

	const advisory = `<li><p>Excessive CPU usage in TLS 1.3 with ssl_early_data<br><a href="https://my.f5.com/manage/s/article/K000163947">Advisory</a><br><a href="https://www.cve.org/CVERecord?id=CVE-2026-132779">CVE-2026-132779</a><br>Not vulnerable: 1.31.10+, 1.30.8+<br>Vulnerable: 1.21.4-1.31.9</p></li>`

	if err := parseNginxVulnerabilities(advisory); err != nil {
		t.Fatalf("parseNginxVulnerabilities() error = %v", err)
	}

	vul, ok := vulMap["nginx:CVE-2026-132779"]
	if !ok {
		t.Fatal("Nginx advisory without Severity was not parsed")
	}
	if vul.Description != "Excessive CPU usage in TLS 1.3 with ssl_early_data" {
		t.Errorf("Description = %q", vul.Description)
	}
	if vul.Severity != common.Unknown {
		t.Errorf("Severity = %q, want %q", vul.Severity, common.Unknown)
	}
	if vul.Link != "https://my.f5.com/manage/s/article/K000163947" {
		t.Errorf("Link = %q", vul.Link)
	}

	wantAffected := []common.AppModuleVersion{{OpCode: "gteq", Version: "1.21.4"}, {OpCode: "lteq", Version: "1.31.9"}}
	if !reflect.DeepEqual(vul.AffectedVer, wantAffected) {
		t.Errorf("AffectedVer = %#v, want %#v", vul.AffectedVer, wantAffected)
	}
	wantFixed := []common.AppModuleVersion{{OpCode: "gteq", Version: "1.31.10"}, {OpCode: "gteq", Version: "1.30.8"}}
	if !reflect.DeepEqual(vul.FixedVer, wantFixed) {
		t.Errorf("FixedVer = %#v, want %#v", vul.FixedVer, wantFixed)
	}
}

func TestOpensslVulVersion(t *testing.T) {
	lines := []string{
		"		<li>from 1.0.1 before 1.0.1u </li>",
		"<li>from 1.0.2 before 1.0.2i </li>\n<li>from 1.0.4 before 1.0.5d </li>",
	}
	affected := [][]common.AppModuleVersion{
		[]common.AppModuleVersion{
			{"lt", "1.0.1u"}, {"gteq", "1.0.1"},
		},
		[]common.AppModuleVersion{
			{"lt", "1.0.2i"}, {"gteq", "1.0.2"}, {"orlt", "1.0.5d"}, {"gteq", "1.0.4"},
		},
	}

	for i, line := range lines {
		_, av, _ := getOpensslVulVersion("cve1", line)
		if !reflect.DeepEqual(av, affected[i]) {
			t.Errorf("Error parsing openssl affected version: i=%d", i)
			t.Errorf("    expected: %s", affected[i])
			t.Errorf("    actual:   %s", av)
		}
	}
}
