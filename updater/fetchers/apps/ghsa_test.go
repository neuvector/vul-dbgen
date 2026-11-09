package apps

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vul-dbgen/common"
)

func TestInferPhpBranchBound(t *testing.T) {
	tests := []struct {
		name     string
		input    []common.AppModuleVersion
		expected []common.AppModuleVersion
	}{
		{
			name:  "bare lt gets lower bound",
			input: []common.AppModuleVersion{{OpCode: "lt", Version: "8.4.27"}},
			expected: []common.AppModuleVersion{
				{OpCode: "gteq", Version: "8.4.0"},
				{OpCode: "andlt", Version: "8.4.27"},
			},
		},
		{
			name:  "bare lteq gets lower bound",
			input: []common.AppModuleVersion{{OpCode: "lteq", Version: "8.3.36"}},
			expected: []common.AppModuleVersion{
				{OpCode: "gteq", Version: "8.3.0"},
				{OpCode: "andlteq", Version: "8.3.36"},
			},
		},
		{
			name: "already bounded range is unchanged",
			input: []common.AppModuleVersion{
				{OpCode: "gteq", Version: "8.4.0"},
				{OpCode: "andlt", Version: "8.4.27"},
			},
			expected: []common.AppModuleVersion{
				{OpCode: "gteq", Version: "8.4.0"},
				{OpCode: "andlt", Version: "8.4.27"},
			},
		},
		{
			name:     "gt opcode is unchanged",
			input:    []common.AppModuleVersion{{OpCode: "gt", Version: "8.4.0"}},
			expected: []common.AppModuleVersion{{OpCode: "gt", Version: "8.4.0"}},
		},
		{
			name:     "empty input is unchanged",
			input:    []common.AppModuleVersion{},
			expected: []common.AppModuleVersion{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, inferPhpBranchBound(tc.input))
		})
	}
}

// TestCleanupVersionOnly cleans up .jreXX version for now.
func TestCleanupVersion(t *testing.T) {
	testcases := []struct {
		version  string
		expected string
	}{
		{
			version:  "1.0.0.jar",
			expected: "1.0.0.jar",
		},
		{
			version:  "1.0.0.war",
			expected: "1.0.0.war",
		},
		{
			version:  "1.0.0",
			expected: "1.0.0",
		},
		{
			version:  "1.0.0.jre11",
			expected: "1.0.0",
		},
		{
			version:  "1.0.0.jre17",
			expected: "1.0.0",
		},
		{
			version:  "1.0.0.jre21",
			expected: "1.0.0",
		},
	}
	for _, testcase := range testcases {
		actual := cleanupVersion(testcase.version)
		require.Equal(t, testcase.expected, actual)
	}
}
