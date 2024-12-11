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
