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
		[]string{">= 1.3.1", "~> 1.2.2", "~> 1.1.1", "~> 1.0.4"},
	}
	affected := [][]common.AppModuleVersion{
		// []ModuleVersion{{"lt", "2.12.5"}, {"gteq", "3.0.0"}, {"andlt", "3.7.2"}, {"gteq", "4.0.0"}, {"andlt", "4.0.0.beta8"}},
		[]common.AppModuleVersion{{"lt", "1.3.1"}, {"orlt", "1.2.2,1.2"}, {"orlt", "1.1.1,1.1"}, {"orlt", "1.0.4,1.0"}},
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

func TestOpensslVulVersion(t *testing.T) {
	lines := []string{
		"<ul><li>Fixed in OpenSSL 3.2.2 <a href=\"https://github.com/openssl/openssl/commit/e9d7083e241670332e0443da0f0d4ffb52829f08\">(git commit)</a> (Affected since 3.2.0)</li><li>Fixed in OpenSSL 3.1.6 <a href=\"https://github.com/openssl/openssl/commit/7e4d731b1c07201ad9374c1cd9ac5263bdf35bce\">(git commit)</a> (Affected since 3.1.0)</li><li>Fixed in OpenSSL 3.0.14 <a href=\"https://github.com/openssl/openssl/commit/b52867a9f618bb955bed2a3ce3db4d4f97ed8e5d\">(git commit)</a> (Affected since 3.0.0)</li><li>Fixed in OpenSSL 1.1.1y <a href=\"/support/contracts.html?giturl=https://github.openssl.org/openssl/extended-releases/commit/5f8d25770ae6437db119dfc951e207271a326640\">(premium support)</a> (Affected since 1.1.1)</li></ul>",
		"<ul><li>Fixed in OpenSSL 0.9.8h (Affected since 0.9.8f)</li></ul>",
		"<ul><li>Fixed in OpenSSL fips-1.1.2 (Affected since fips-1.1.1)</li></ul>",
		"<ul><li>Fixed in OpenSSL 0.9.8j (Affected since 0.9.8)</li></ul>",
	}
	affected := [][]common.AppModuleVersion{
		[]common.AppModuleVersion{
			{"lt", "3.2.2"}, {"gteq", "3.2.0"}, {"orlt", "3.1.6"}, {"gteq", "3.1.0"},
			{"orlt", "3.0.14"}, {"gteq", "3.0.0"}, {"orlt", "1.1.1y"}, {"gteq", "1.1.1"}},
		[]common.AppModuleVersion{
			{"lt", "0.9.8h"}, {"gteq", "0.9.8f"}},
		[]common.AppModuleVersion{
			{"lt", "fips-1.1.2"}, {"gteq", "fips-1.1.1"}},
		[]common.AppModuleVersion{
			{"lt", "0.9.8j"}, {"gteq", "0.9.8"}},
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
