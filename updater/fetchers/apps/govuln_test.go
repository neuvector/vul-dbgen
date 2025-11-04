package apps

import (
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestParseAffectedRanges(t *testing.T) {
	ecosystemSpecific, err := structpb.NewStruct(map[string]interface{}{
		"custom_ranges": []interface{}{
			map[string]interface{}{
				"type": "ECOSYSTEM",
				"events": []interface{}{
					map[string]interface{}{"introduced": "0.0.0-20230727023453-1c4957d53911"},
					map[string]interface{}{"fixed": "0.0.0-20251020133207-084a437033b4"},
					map[string]interface{}{"introduced": "5.3.0"},
					map[string]interface{}{"fixed": "5.3.5"},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Failed to create ecosystem_specific: %v", err)
	}

	testCases := []struct {
		name             string
		vuln             *osvschema.Vulnerability
		expectedAffected []struct{ version, opCode string }
		expectedFixed    []struct{ version, opCode string }
	}{
		{
			name: "No custom ranges: only semver events",
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
			},
			expectedFixed: []struct{ version, opCode string }{
				{version: "1.2.3", opCode: "lt"},
			},
		},
		{
			name: "0 introduced and no fixed version behind, should be ignored",
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
						EcosystemSpecific: ecosystemSpecific,
					},
				},
			},
			expectedAffected: []struct{ version, opCode string }{
				{version: "0.0.0-20230727023453-1c4957d53911", opCode: "gteq"},
				{version: "5.3.0", opCode: "gteq"},
			},
			expectedFixed: []struct{ version, opCode string }{
				{version: "0.0.0-20251020133207-084a437033b4", opCode: "lt"},
				{version: "5.3.5", opCode: "lt"},
			},
		},
		{
			name: "0 introduced and no fixed version behind",
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
						EcosystemSpecific: ecosystemSpecific,
					},
				},
			},
			expectedAffected: []struct{ version, opCode string }{
				{version: "0.0.0-20230727023453-1c4957d53911", opCode: "gteq"},
				{version: "5.3.0", opCode: "gteq"},
				{version: "1.0.0", opCode: "gteq"},
			},
			expectedFixed: []struct{ version, opCode string }{
				{version: "0.0.0-20251020133207-084a437033b4", opCode: "lt"},
				{version: "5.3.5", opCode: "lt"},
				{version: "1.2.3", opCode: "lt"},
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

			require.Equal(t, len(tc.expectedFixed), len(appVul.FixedVer),
				"Expected %d FixedVer, got %d", len(tc.expectedFixed), len(appVul.FixedVer))
			for i, expected := range tc.expectedFixed {
				require.Equal(t, expected.version, appVul.FixedVer[i].Version,
					"FixedVer[%d] version mismatch", i)
				require.Equal(t, expected.opCode, appVul.FixedVer[i].OpCode,
					"FixedVer[%d] opCode mismatch", i)
			}
		})
	}
}
