package photon

import (
	"strings"
	"testing"

	"github.com/vul-dbgen/common"
)

const photonOVALFixture = `<oval_definitions>
  <definitions>
    <definition class="patch" id="oval:com.vmware.phsa:def:1" version="1">
      <metadata>
        <affected family="unix"><platform>Photon 5</platform></affected>
        <reference ref_id="PHSA:00003:5.0:860" ref_url="https://example.com/PHSA-2026-00003" source="PHSA"/>
        <reference ref_id="CVE:00003:CVE-2022-1304" ref_url="https://example.com/CVE-2022-1304" source="CVE"/>
        <description>e2fsprogs security update</description>
        <advisory>
          <severity>Important</severity>
          <issued date="2026-05-30"/>
          <updated date="2026-05-31"/>
          <cve>CVE-2022-1304</cve>
          <cve>CVE-2025-14762</cve>
        </advisory>
      </metadata>
      <criteria operator="AND">
        <criteria operator="OR">
          <criteria operator="AND">
            <criterion comment="e2fsprogs-libs is earlier than 0:1.46.5-5.0.1.ph5" test_ref="oval:com.vmware.phsa:tst:libs"/>
            <criterion comment="e2fsprogs-libs is signed with VMware key" test_ref="oval:com.vmware.phsa:tst:signing"/>
          </criteria>
          <criterion comment="e2fsprogs is earlier than 0:1.46.5-5.0.1.ph5" test_ref="oval:com.vmware.phsa:tst:e2fsprogs"/>
          <criterion comment="expat is earlier than N/A" test_ref="oval:com.vmware.phsa:tst:expat"/>
        </criteria>
      </criteria>
    </definition>
  </definitions>
  <tests>
    <rpminfo_test id="oval:com.vmware.phsa:tst:libs"><object object_ref="oval:com.vmware.phsa:obj:libs"/><state state_ref="oval:com.vmware.phsa:ste:libs"/></rpminfo_test>
    <rpminfo_test id="oval:com.vmware.phsa:tst:signing"><object object_ref="oval:com.vmware.phsa:obj:libs"/><state state_ref="oval:com.vmware.phsa:ste:signing"/></rpminfo_test>
    <rpminfo_test id="oval:com.vmware.phsa:tst:e2fsprogs"><object object_ref="oval:com.vmware.phsa:obj:e2fsprogs"/><state state_ref="oval:com.vmware.phsa:ste:e2fsprogs"/></rpminfo_test>
    <rpminfo_test id="oval:com.vmware.phsa:tst:expat"><object object_ref="oval:com.vmware.phsa:obj:expat"/><state state_ref="oval:com.vmware.phsa:ste:expat"/></rpminfo_test>
  </tests>
  <objects>
    <rpminfo_object id="oval:com.vmware.phsa:obj:libs"><name>e2fsprogs-libs</name></rpminfo_object>
    <rpminfo_object id="oval:com.vmware.phsa:obj:e2fsprogs"><name>e2fsprogs</name></rpminfo_object>
    <rpminfo_object id="oval:com.vmware.phsa:obj:expat"><name>expat</name></rpminfo_object>
  </objects>
  <states>
    <rpminfo_state id="oval:com.vmware.phsa:ste:libs"><evr operation="less than">0:1.46.5-5.0.1.ph5</evr></rpminfo_state>
    <rpminfo_state id="oval:com.vmware.phsa:ste:signing"><signature_keyid operation="equals">c0b5e0ab66fd4949</signature_keyid></rpminfo_state>
    <rpminfo_state id="oval:com.vmware.phsa:ste:e2fsprogs"><evr operation="less than">0:1.46.5-5.0.1.ph5</evr></rpminfo_state>
    <rpminfo_state id="oval:com.vmware.phsa:ste:expat"><evr operation="less than">N/A</evr></rpminfo_state>
  </states>
</oval_definitions>`

func TestParsePhotonOVAL(t *testing.T) {
	vulnerabilities, err := parsePhotonOVAL(strings.NewReader(photonOVALFixture))
	if err != nil {
		t.Fatalf("parse Photon OVAL: %v", err)
	}
	if len(vulnerabilities) != 2 {
		t.Fatalf("expected one vulnerability per CVE, got %d", len(vulnerabilities))
	}

	byCVE := make(map[string]common.Vulnerability, len(vulnerabilities))
	for _, vulnerability := range vulnerabilities {
		byCVE[vulnerability.Name] = vulnerability
	}
	for _, cve := range []string{"CVE-2022-1304", "CVE-2025-14762"} {
		vulnerability, ok := byCVE[cve]
		if !ok {
			t.Errorf("missing vulnerability for %s", cve)
			continue
		}
		if vulnerability.Namespace != "photon:5" {
			t.Errorf("%s namespace = %q, want photon:5", cve, vulnerability.Namespace)
		}
		if vulnerability.Severity != common.High {
			t.Errorf("%s severity = %q, want %q", cve, vulnerability.Severity, common.High)
		}
		if len(vulnerability.CVEs) != 1 || vulnerability.CVEs[0].Name != cve {
			t.Errorf("%s CVEs = %#v, want itself", cve, vulnerability.CVEs)
		}

		features := fixedInByName(vulnerability.FixedIn)
		if len(features) != 4 {
			t.Errorf("%s fixed packages = %d, want 4 (without signing criterion)", cve, len(features))
		}
		libs, ok := features["e2fsprogs-libs"]
		if !ok {
			t.Errorf("%s missing e2fsprogs-libs", cve)
		} else if libs.Version.String() != "1.46.5-5.0.1.ph5" {
			t.Errorf("e2fsprogs-libs version = %q, want 1.46.5-5.0.1.ph5", libs.Version.String())
		}
		if _, ok := features["e2fsprogs"]; !ok {
			t.Errorf("%s missing e2fsprogs", cve)
		}
		if _, ok := features["expat"]; !ok {
			t.Errorf("%s missing expat", cve)
		}
		expatLibs, ok := features["expat-libs"]
		if !ok {
			t.Errorf("%s missing expat-libs alias", cve)
		} else if expatLibs.Version != common.MaxVersion {
			t.Errorf("expat-libs version = %q, want %q", expatLibs.Version.String(), common.MaxVersion.String())
		}
	}
}

func fixedInByName(fixedIn []common.FeatureVersion) map[string]common.FeatureVersion {
	features := make(map[string]common.FeatureVersion, len(fixedIn))
	for _, feature := range fixedIn {
		features[feature.Name] = feature
	}
	return features
}
