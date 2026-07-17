package updater

import "testing"

func TestShouldSkipDescription(t *testing.T) {
	cases := []struct {
		description string
		want        bool
	}{
		{
			description: "Rejected reason: CVE confirmed to be a false positive",
			want:        true,
		},
		{
			description: "Withdrawn Advisory: go.etcd.io/bbolt affected by index out-of-range vulnerability",
			want:        true,
		},
		{
			description: "Regular advisory description",
			want:        false,
		},
	}

	for _, tc := range cases {
		if got := ShouldSkipDescription(tc.description); got != tc.want {
			t.Fatalf("ShouldSkipDescription(%q) = %v, want %v", tc.description, got, tc.want)
		}
	}
}
