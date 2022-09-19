package mariner

import (
	"strings"
	"testing"
	"time"

	"github.com/vul-dbgen/common"
	"github.com/vul-dbgen/updater"
)

const testOval = `<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5" xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5" xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://oval.mitre.org/XMLSchema/oval-common-5 https://oval.mitre.org/language/version5.11/ovaldefinition/complete/oval-common-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5 https://oval.mitre.org/language/version5.11/ovaldefinition/complete/oval-definitions-schema.xsd http://oval.mitre.org/XMLSchema/oval-definitions-5#linux https://oval.mitre.org/language/version5.11/ovaldefinition/complete/linux-definitions-schema.xsd ">
<generator>
  <oval:product_name>CBL-Mariner OVAL Definition Generator</oval:product_name>
  <oval:product_version>8</oval:product_version>
  <oval:schema_version>5.11</oval:schema_version>
  <oval:timestamp>2022-03-11T13:01:34.506548911Z</oval:timestamp>
  <oval:content_version>1647003694</oval:content_version>
</generator>
<definitions>
  <definition class="vulnerability" id="oval:com.microsoft.cbl-mariner:def:2666" version="1647003694">
	<metadata>
	  <title>CVE-2000-0803 affecting package groff 1.22.3</title>
	  <affected family="unix">
		<platform>CBL-Mariner</platform>
	  </affected>
	  <reference ref_id="CVE-2000-0803" ref_url="https://nvd.nist.gov/vuln/detail/CVE-2000-0803" source="CVE"/>
	  <patchable>true</patchable>
	  <advisory_date>2020-10-08T18:09:51Z</advisory_date>
	  <advisory_id>2666</advisory_id>
	  <severity>Critical</severity>
	  <description>CVE-2000-0803 affecting package groff 1.22.3. A patched version of the package is available.</description>
	</metadata>
	<criteria operator="AND">
	  <criterion comment="Package groff is earlier than 1.22.3-5, affected by CVE-2000-0803" test_ref="oval:com.microsoft.cbl-mariner:tst:1647003694000000"/>
	</criteria>
  </definition>
  <definition class="vulnerability" id="oval:com.microsoft.cbl-mariner:def:3173" version="1647003694">
	<metadata>
	  <title>CVE-2008-3914 affecting package clamav 0.101.2</title>
	  <affected family="unix">
		<platform>CBL-Mariner</platform>
	  </affected>
	  <reference ref_id="CVE-2008-3914" ref_url="https://nvd.nist.gov/vuln/detail/CVE-2008-3914" source="CVE"/>
	  <patchable>true</patchable>
	  <advisory_date>2021-05-06T23:56:51Z</advisory_date>
	  <advisory_id>3173</advisory_id>
	  <severity>Critical</severity>
	  <description>CVE-2008-3914 affecting package clamav 0.101.2. An upgraded version of the package is available that resolves this issue.</description>
	</metadata>
	<criteria operator="AND">
	  <criterion comment="Package clamav is earlier than 0.103.2-1, affected by CVE-2008-3914" test_ref="oval:com.microsoft.cbl-mariner:tst:1647003694000003"/>
	</criteria>
  </definition>
</definitions>
  <tests>
  <linux-def:rpminfo_test check="at least one" comment="Package groff is earlier than 1.22.3-5, affected by CVE-2000-0803" id="oval:com.microsoft.cbl-mariner:tst:1647003694000000" version="1647003694">
	<linux-def:object object_ref="oval:com.microsoft.cbl-mariner:obj:1647003694000001"/>
	<linux-def:state state_ref="oval:com.microsoft.cbl-mariner:ste:1647003694000002"/>
  </linux-def:rpminfo_test>
  <linux-def:rpminfo_test check="at least one" comment="Package clamav is earlier than 0.103.2-1, affected by CVE-2008-3914" id="oval:com.microsoft.cbl-mariner:tst:1647003694000003" version="1647003694">
	<linux-def:object object_ref="oval:com.microsoft.cbl-mariner:obj:1647003694000004"/>
	<linux-def:state state_ref="oval:com.microsoft.cbl-mariner:ste:1647003694000005"/>
  </linux-def:rpminfo_test>
  </tests>
  <objects>
  <linux-def:rpminfo_object id="oval:com.microsoft.cbl-mariner:obj:1647003694000001" version="1647003694">
	<linux-def:name>groff</linux-def:name>
  </linux-def:rpminfo_object>
  <linux-def:rpminfo_object id="oval:com.microsoft.cbl-mariner:obj:1647003694000004" version="1647003694">
	<linux-def:name>clamav</linux-def:name>
  </linux-def:rpminfo_object>
  </objects>
  <states>
  <linux-def:rpminfo_state id="oval:com.microsoft.cbl-mariner:ste:1647003694000002" version="1647003694">
	<linux-def:evr datatype="evr_string" operation="less than">0:1.22.3-5.cm1</linux-def:evr>
  </linux-def:rpminfo_state>
  <linux-def:rpminfo_state id="oval:com.microsoft.cbl-mariner:ste:1647003694000005" version="1647003694">
	<linux-def:evr datatype="evr_string" operation="less than">0:0.103.2-1.cm1</linux-def:evr>
  </linux-def:rpminfo_state>
  </states>
</oval_definitions>`

func TestParseOval(t *testing.T) {
	reader := strings.NewReader(testOval)
	expectedResult := updater.Vulnerability{
		Name:        "CVE-2000-0803",
		Description: "CVE-2000-0803 affecting package groff 1.22.3. A patched version of the package is available.",
		Link:        "https://nvd.nist.gov/vuln/detail/CVE-2000-0803",
		IssuedDate:  time.Time{},
		Severity:    "Critical",
	}
	expectedResult2 := updater.Vulnerability{
		Name:        "CVE-2008-3914",
		Description: "CVE-2008-3914 affecting package clamav 0.101.2. An upgraded version of the package is available that resolves this issue.",
		Link:        "https://nvd.nist.gov/vuln/detail/CVE-2008-3914",
		IssuedDate:  time.Time{},
		Severity:    "Critical",
	}
	defTime := strings.Split("2020-10-08T18:09:51Z", "T")[0]
	if time, err := time.Parse("2006-01-02", defTime); err == nil {
		expectedResult.IssuedDate = time
	} else {
		t.Errorf("TestParseOval Error with time parsing: %s", err)
	}
	defTime = strings.Split("2021-05-06T23:56:51Z", "T")[0]
	if time, err := time.Parse("2006-01-02", defTime); err == nil {
		expectedResult2.IssuedDate = time
	} else {
		t.Errorf("TestParseOval Error with time parsing: %s", err)
	}
	version, err := common.NewVersion("0:1.22.3-5.cm1")
	if err != nil {
		t.Errorf("Error parsing version: %s", err)
	}
	version2, err := common.NewVersion("0.103.2-1.cm1")
	if err != nil {
		t.Errorf("Error parsing version: %s", err)
	}

	featureVersion := updater.FeatureVersion{
		Feature: updater.Feature{
			Name:      "groff",
			Namespace: "mariner:1.0",
		},
		Version: version,
	}
	featureVersion2 := updater.FeatureVersion{
		Feature: updater.Feature{
			Name:      "clamav",
			Namespace: "mariner:1.0",
		},
		Version: version2,
	}

	expectedResult.FixedIn = []updater.FeatureVersion{featureVersion}
	expectedResult2.FixedIn = []updater.FeatureVersion{featureVersion2}
	vulns, err := parseMarinerOval(reader)
	if err != nil {
		t.Errorf("TestParseOval Error with parseMarinerOval: %s", err)
	}
	if len(vulns) < 2 {
		t.Errorf("TestParseOval Error: Not all entries were parsed")
	} else if vulns[0].Name != expectedResult.Name || vulns[0].Description != expectedResult.Description || vulns[0].Link != expectedResult.Link ||
		vulns[0].IssuedDate != expectedResult.IssuedDate || vulns[0].Severity != expectedResult.Severity || vulns[0].FixedIn[0] != expectedResult.FixedIn[0] {
		t.Errorf("Expected vuln mismatch: \nexpected: %v\nreceived: %v", expectedResult, vulns[0])
	} else if vulns[1].Name != expectedResult2.Name || vulns[1].Description != expectedResult2.Description || vulns[1].Link != expectedResult2.Link ||
		vulns[1].IssuedDate != expectedResult2.IssuedDate || vulns[1].Severity != expectedResult2.Severity || vulns[1].FixedIn[0] != expectedResult2.FixedIn[0] {
		t.Errorf("Expected vuln mismatch: \nexpected: %v\nreceived: %v", expectedResult2, vulns[1])
	}
}
