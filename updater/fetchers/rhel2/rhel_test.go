package rhel2

import (
	"testing"

	"github.com/vul-dbgen/common"
)

func TestRHSACulling(t *testing.T) {
	fixedIn1 := common.FeatureVersion{
		Name: "",
		Feature: common.Feature{
			Name:      "ldap",
			Namespace: "centos7",
		},
		Version: common.Version{},
		MinVer:  common.Version{},
	}
	fixedIn2 := common.FeatureVersion{
		Name: "",
		Feature: common.Feature{
			Name:      "ldap",
			Namespace: "centos8",
		},
		Version: common.Version{},
		MinVer:  common.Version{},
	}
	fixedIn3 := common.FeatureVersion{
		Name: "",
		Feature: common.Feature{
			Name:      "openldap",
			Namespace: "centos7",
		},
		Version: common.Version{},
		MinVer:  common.Version{},
	}
	cve1 := common.CVE{
		Name: "CVE-2021-2222",
	}
	cve2 := common.CVE{
		Name: "CVE-2021-2223",
	}
	cve3 := common.CVE{
		Name: "CVE-2021-2225",
	}

	full1 := common.Vulnerability{
		Name:      "CVE-2021-2222",
		Namespace: "centos7",
		FixedIn:   []common.FeatureVersion{fixedIn1, fixedIn3},
		CPEs:      []string{},
		CVEs:      []common.CVE{},
	}

	full2 := common.Vulnerability{
		Name:      "RHSA-33",
		Namespace: "centos7",
		FixedIn:   []common.FeatureVersion{fixedIn1},
		CPEs:      []string{},
		CVEs:      []common.CVE{cve1},
	}

	full3 := common.Vulnerability{
		Name:      "RHSA-34",
		Namespace: "centos8",
		FixedIn:   []common.FeatureVersion{fixedIn2, fixedIn3},
		CPEs:      []string{},
		CVEs:      []common.CVE{cve2, cve3},
	}

	full4 := common.Vulnerability{
		Name:      "CVE-2021-2223",
		Namespace: "centos8",
		FixedIn:   []common.FeatureVersion{fixedIn2},
		CPEs:      []string{},
		CVEs:      []common.CVE{},
	}
	full5 := common.Vulnerability{
		Name:      "CVE-2021-2224",
		Namespace: "centos8",
		FixedIn:   []common.FeatureVersion{fixedIn1, fixedIn2, fixedIn3},
		CPEs:      []string{},
		CVEs:      []common.CVE{},
	}
	full6 := common.Vulnerability{
		Name:      "CVE-2021-2225",
		Namespace: "centos8",
		FixedIn:   []common.FeatureVersion{fixedIn2, fixedIn3},
		CPEs:      []string{},
		CVEs:      []common.CVE{},
	}
	fullVulns := []common.Vulnerability{full1, full2, full3, full4, full5, full6}

	vulns := cullAllVulns(fullVulns)
	if len(vulns) != 4 {
		t.Fail()
		t.Logf("FAIL - Length of vulnerabilities expected: 4, Found: %v\n", len(vulns))
	}

	for _, entry := range vulns {
		switch entry.Name {
		case "CVE-2021-2222":
			if len(entry.FixedIn) != 1 {
				t.Fail()
				t.Logf("full1 FixedIn len != 1")
			} else if entry.FixedIn[0] != fixedIn3 {
				t.Fail()
				t.Logf("full1 FixedIn culled incorrectly")
			}
		case "RHSA-33":
			if len(entry.FixedIn) != 1 {
				t.Fail()
				t.Logf("full2 FixedIn len != 1")
			}
		case "RHSA-34":
			if len(entry.FixedIn) != 2 {
				t.Fail()
				t.Logf("full3 FixedIn len != 2")
			}
		case "CVE-2021-2223":
			t.Fail()
			t.Logf("full4 not culled")
		case "CVE-2021-2224":
			if len(entry.FixedIn) != 3 {
				t.Fail()
				t.Logf("full5 FixedIn len != 3")
			}
		case "CVE-2021-2225":
			t.Fail()
			t.Logf("full4 not culled")
		}

	}
}
