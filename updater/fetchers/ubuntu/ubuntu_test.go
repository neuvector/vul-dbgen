package ubuntu

import (
	"testing"

	"strings"

	"github.com/vul-dbgen/common"
)

func TestReleaseParsing(t *testing.T) {
	lines := []string{
		"xenial_apparmor: ignored (end of standard support, was deferred)",
		"esm-infra/xenial_apparmor: deferred",
	}

	for _, line := range lines {
		affectsCaptureArr := affectsCaptureRegexp.FindAllStringSubmatch(line, -1)
		if len(affectsCaptureArr) > 0 {
			affectsCapture := affectsCaptureArr[0]

			md := map[string]string{}
			for i, n := range affectsCapture {
				md[affectsCaptureRegexpNames[i]] = strings.TrimSpace(n)
			}
			if _, ok := common.UbuntuReleasesMapping[md["release"]]; !ok {
				t.Errorf("Unknown release: %s", md["release"])
			}
		} else {
			t.Errorf("Unable to parse affected release: %s", line)
		}
	}
}
