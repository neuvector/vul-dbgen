package chainguardv2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseAdvisoryFiltersAndDeduplicatesByEcosystem(t *testing.T) {
	body := []byte(`{
		"id": "CGA-test-1234",
		"published": "2026-04-10T00:00:00Z",
		"modified": "2026-04-11T00:00:00Z",
		"upstream": ["CVE-2026-0001", "GHSA-test-1234", "CVE-2026-0001"],
		"affected": [
			{
				"package": {"ecosystem": "Wolfi", "name": "haproxy-3.1", "purl": "pkg:apk/wolfi/haproxy-3.1?arch=x86_64"},
				"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1.7-r0"}]}]
			},
			{
				"package": {"ecosystem": "Wolfi", "name": "haproxy-3.1", "purl": "pkg:apk/wolfi/haproxy-3.1?arch=aarch64"},
				"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1.7-r0"}]}]
			},
			{
				"package": {"ecosystem": "Chainguard", "name": "haproxy-3.1", "purl": "pkg:apk/chainguard/haproxy-3.1?arch=x86_64"},
				"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1.8-r0"}]}]
			},
			{
				"package": {"ecosystem": "Wolfi", "name": "haproxy-3.2", "purl": "pkg:apk/wolfi/haproxy-3.2?arch=x86_64"},
				"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
			}
		]
	}`)

	vulns, err := parseAdvisory(body, "Wolfi", "wolfi:rolling")
	require.NoError(t, err)
	require.Len(t, vulns, 1)
	require.Equal(t, "CVE-2026-0001", vulns[0].Name)
	require.Equal(t, "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-0001", vulns[0].Link)
	require.Len(t, vulns[0].FixedIn, 1)
	require.Equal(t, "wolfi:rolling", vulns[0].FixedIn[0].Feature.Namespace)
	require.Equal(t, "haproxy-3.1", vulns[0].FixedIn[0].Feature.Name)
	require.Equal(t, "3.1.7-r0", vulns[0].FixedIn[0].Version.String())
}

func TestParseAdvisorySkipsEntriesWithoutCVEs(t *testing.T) {
	body := []byte(`{
		"id": "CGA-test-5678",
		"affected": [
			{
				"package": {"ecosystem": "Wolfi", "name": "pkg"},
				"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0.0-r1"}]}]
			}
		],
		"upstream": ["GHSA-only"]
	}`)

	vulns, err := parseAdvisory(body, "Wolfi", "wolfi:rolling")
	require.NoError(t, err)
	require.Empty(t, vulns)
}
