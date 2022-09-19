package amazon

import (
	"testing"

	"strings"
)

func TestCVELink(t *testing.T) {
	cases := map[string]string{
		"https://access.redhat.com/security/cve/CVE-2020-2604":  "CVE-2020-2604",
		"https://access.redhat.com/security/cve/CVE-2020-2604/": "",
		"CVE-2020-2604":                          "CVE-2020-2604",
		"https://access.redhat.com/security/cve": "",
	}

	for link, cve := range cases {
		c := parseCVELink(link)
		if c != cve {
			t.Errorf("Expected: %s, Actual: %s\n", cve, c)
		}
	}
}

type netMethodMock struct {
}

func (net netMethodMock) DownloadHTMLPage(url string) (string, error) {
	return alasTest, nil
}

func TestParseListPage(t *testing.T) {
	var net netMethodMock

	vuls, _ := parseAlasListPage("", alasListTest, net)
	if len(vuls) != 1288 {
		t.Errorf("Unexpected vulnerability count. %v", len(vuls))
	}

	for _, v := range vuls {
		name := strings.TrimRight(v.name, ".html")
		if name == "ALAS-2020-1345" {
			if !strings.HasPrefix(v.dateCreate.String(), "2020-02-20") {
				t.Errorf("Unexpected cve date: %s", v.dateCreate.String())
			}
			if len(v.cves) != 7 {
				t.Errorf("Unexpected cve count: %d", len(v.cves))
			}
		}
	}
}

func TestParseAlasPage(t *testing.T) {
	var net netMethodMock

	_, vers, _ := parseAlasPage(alasTest, []string{"java-1.8.0-openjdk"}, net)
	if len(vers) != 1 {
		t.Errorf("Unexpected vulnerability alas parsing result, %+v", vers)
	}
}

/*
func TestDownload(t *testing.T) {
	plain, _ := downloadPage(alasUri + "ALAS-2020-1345.html")
	t.Error(plain)
}
*/
