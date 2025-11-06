package apps

import (
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func mustCreateEcosystemSpecific(t *testing.T, data map[string]interface{}) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(data)
	if err != nil {
		t.Fatalf("Failed to create ecosystem_specific: %v", err)
	}
	return s
}

func TestParseAffectedRanges(t *testing.T) {
	ecosystemSpecificWithMissingFix := mustCreateEcosystemSpecific(t, map[string]interface{}{
		"custom_ranges": []interface{}{
			map[string]interface{}{
				"type": "ECOSYSTEM",
				"events": []interface{}{
					map[string]interface{}{"introduced": "0.0.0-20230727023453-1c4957d53911"},
					map[string]interface{}{"fixed": "0.0.0-20251020133207-084a437033b4"},
					map[string]interface{}{"introduced": "5.2.0"},
					map[string]interface{}{"introduced": "5.3.0"},
					map[string]interface{}{"fixed": "5.3.5"},
				},
			},
		},
	})

	ecosystemSpecific := mustCreateEcosystemSpecific(t, map[string]interface{}{
		"custom_ranges": []interface{}{
			map[string]interface{}{
				"type": "ECOSYSTEM",
				"events": []interface{}{
					map[string]interface{}{"introduced": "5.2.0"},
					map[string]interface{}{"fixed": "5.3.0"},
					map[string]interface{}{"introduced": "5.3.0"},
					map[string]interface{}{"fixed": "5.3.4"},
					map[string]interface{}{"introduced": "5.4.0"},
					map[string]interface{}{"fixed": "5.4.7"},
				},
			},
		},
	})

	testCases := []struct {
		name             string
		vuln             *osvschema.Vulnerability
		expectedAffected []struct{ version, opCode string }
	}{
		{
			name: "SemverOnly_ZeroIntroduced_NoCustomRanges",
			vuln: &osvschema.Vulnerability{
				Id:        "GO-2025-0002",
				Details:   "Test vulnerability without custom ranges",
				Summary:   "Test summary",
				Published: timestamppb.Now(),
				Modified:  timestamppb.Now(),
				Affected: []*osvschema.Affected{
					{
						Package: &osvschema.Package{
							Name:      "github.com/example/package",
							Ecosystem: "Go",
						},
						Ranges: []*osvschema.Range{
							{
								Type: osvschema.Range_SEMVER,
								Events: []*osvschema.Event{
									{Introduced: "0"},
								},
							},
						},
						EcosystemSpecific: nil,
					},
				},
			},
			expectedAffected: []struct{ version, opCode string }{
				{version: "0", opCode: "gteq"},
			},
		},
		{
			name: "SemverEvents_IntroducedAndFixed_NoCustomRanges",
			vuln: &osvschema.Vulnerability{
				Id:        "GO-2025-0002",
				Details:   "Test vulnerability without custom ranges",
				Summary:   "Test summary",
				Published: timestamppb.Now(),
				Modified:  timestamppb.Now(),
				Affected: []*osvschema.Affected{
					{
						Package: &osvschema.Package{
							Name:      "github.com/example/package",
							Ecosystem: "Go",
						},
						Ranges: []*osvschema.Range{
							{
								Type: osvschema.Range_SEMVER,
								Events: []*osvschema.Event{
									{Introduced: "1.0.0"},
									{Fixed: "1.2.3"},
								},
							},
						},
						EcosystemSpecific: nil,
					},
				},
			},
			expectedAffected: []struct{ version, opCode string }{
				{version: "1.0.0", opCode: "gteq"},
				{version: "1.2.3", opCode: "andlt"},
			},
		},
		{
			name: "CustomRanges_OverrideZeroIntroduced_SingleAffected",
			vuln: &osvschema.Vulnerability{
				Id:        "GO-2025-0001",
				Details:   "Test vulnerability",
				Summary:   "Test summary",
				Published: timestamppb.Now(),
				Modified:  timestamppb.Now(),
				Affected: []*osvschema.Affected{
					{
						Package: &osvschema.Package{
							Name:      "github.com/example/package",
							Ecosystem: "Go",
						},
						Ranges: []*osvschema.Range{
							{
								Type: osvschema.Range_SEMVER,
								Events: []*osvschema.Event{
									{Introduced: "0"}, // This should be ignored
								},
							},
						},
						EcosystemSpecific: ecosystemSpecificWithMissingFix,
					},
				},
			},
			expectedAffected: []struct{ version, opCode string }{
				{version: "0.0.0-20230727023453-1c4957d53911", opCode: "gteq"},
				{version: "0.0.0-20251020133207-084a437033b4", opCode: "andlt"},
				{version: "5.2.0", opCode: "orgteq"},
				{version: "5.3.0", opCode: "andlt"},
				{version: "5.3.0", opCode: "orgteq"},
				{version: "5.3.5", opCode: "andlt"},
				{version: "0", opCode: "orgteq"},
				{version: "0.0.0-20230727023453-1c4957d53911", opCode: "andlt"},
			},
		},
		{
			name: "CustomAndSemverRanges_ZeroIntroducedWithExtraSemver",
			vuln: &osvschema.Vulnerability{
				Id:        "GO-2025-0002",
				Details:   "Test vulnerability without custom ranges",
				Summary:   "Test summary",
				Published: timestamppb.Now(),
				Modified:  timestamppb.Now(),
				Affected: []*osvschema.Affected{
					{
						Package: &osvschema.Package{
							Name:      "github.com/example/package",
							Ecosystem: "Go",
						},
						Ranges: []*osvschema.Range{
							{
								Type: osvschema.Range_SEMVER,
								Events: []*osvschema.Event{
									{Introduced: "0"},
									{Introduced: "1.0.0"},
									{Fixed: "1.2.3"},
								},
							},
						},
						EcosystemSpecific: ecosystemSpecificWithMissingFix,
					},
				},
			},
			expectedAffected: []struct{ version, opCode string }{
				{version: "0.0.0-20230727023453-1c4957d53911", opCode: "gteq"},
				{version: "0.0.0-20251020133207-084a437033b4", opCode: "andlt"},
				{version: "5.2.0", opCode: "orgteq"},
				{version: "5.3.0", opCode: "andlt"},
				{version: "5.3.0", opCode: "orgteq"},
				{version: "5.3.5", opCode: "andlt"},
				{version: "0", opCode: "orgteq"},
				{version: "1.0.0", opCode: "andlt"},
				{version: "1.0.0", opCode: "orgteq"},
				{version: "1.2.3", opCode: "andlt"},
			},
		},
		{
			name: "CustomRanges_MultipleOrGroups",
			vuln: &osvschema.Vulnerability{
				Id:        "GO-2025-0003",
				Details:   "Test multiple ranges",
				Summary:   "Test summary",
				Published: timestamppb.Now(),
				Modified:  timestamppb.Now(),
				Affected: []*osvschema.Affected{
					{
						Package: &osvschema.Package{
							Name:      "github.com/example/package",
							Ecosystem: "Go",
						},
						Ranges: []*osvschema.Range{
							{
								Type: osvschema.Range_SEMVER,
								Events: []*osvschema.Event{
									{Introduced: "0"},
								},
							},
						},
						EcosystemSpecific: ecosystemSpecific,
					},
				},
			},
			// Expected: (>=5.2.0 AND <5.3.0) OR (>=5.3.0 AND <5.3.4) OR (>=5.4.0 AND <5.4.7)
			expectedAffected: []struct{ version, opCode string }{
				{version: "5.2.0", opCode: "gteq"},
				{version: "5.3.0", opCode: "andlt"},
				{version: "5.3.0", opCode: "orgteq"},
				{version: "5.3.4", opCode: "andlt"},
				{version: "5.4.0", opCode: "orgteq"},
				{version: "5.4.7", opCode: "andlt"},
				{version: "0", opCode: "orgteq"},
				{version: "5.2.0", opCode: "andlt"},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			appVuls, _ := convertGoOSVToAppModuleVul(tc.vuln)
			require.Equal(t, 1, len(appVuls), "Expected 1 AppModuleVul, got %d", len(appVuls))

			appVul := appVuls[0]
			require.Equal(t, len(tc.expectedAffected), len(appVul.AffectedVer),
				"Expected %d AffectedVer, got %d", len(tc.expectedAffected), len(appVul.AffectedVer))
			for i, expected := range tc.expectedAffected {
				require.Equal(t, expected.version, appVul.AffectedVer[i].Version,
					"AffectedVer[%d] version mismatch", i)
				require.Equal(t, expected.opCode, appVul.AffectedVer[i].OpCode,
					"AffectedVer[%d] opCode mismatch", i)
			}
		})
	}
}
