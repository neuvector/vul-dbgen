package apps

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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
