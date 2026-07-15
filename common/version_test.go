package common

import "testing"

func TestNewVersionAcceptsCaret(t *testing.T) {
	v, err := NewVersion("1.5.0^20220105.git9f283b7-3.amzn2023.0.6")
	if err != nil {
		t.Fatalf("expected version with caret to parse, got error: %v", err)
	}

	if got := v.String(); got != "1.5.0^20220105.git9f283b7-3.amzn2023.0.6" {
		t.Fatalf("unexpected round-trip version: %s", got)
	}
}
