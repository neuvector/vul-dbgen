package updater

import "strings"

var skippedDescriptionMarkers = []string{
	"rejected reason",
	"withdrawn advisory",
}

func ShouldSkipDescription(description string) bool {
	lowerDescription := strings.ToLower(description)
	for _, marker := range skippedDescriptionMarkers {
		if strings.Contains(lowerDescription, marker) {
			return true
		}
	}

	return false
}
