package updater

import (
	"sync"
	"time"
)

var metadataFetchers = make(map[string]MetadataFetcher)

type VulnerabilityWithLock struct {
	*Vulnerability
	Lock sync.Mutex
}

// MetadataFetcher
type MetadataFetcher interface {
	// Load runs right before the Updater calls AddMetadata for each vulnerabilities.
	Load(Datastore) error

	// AddMetadata adds metadata to the given database.Vulnerability.
	// It is expected that the fetcher uses .Lock.Lock() when manipulating the Metadata map.
	AddMetadata(*VulnerabilityWithLock) error

	LookupMetadata(name string) (string, float64, string, float64, bool)
	AddAffectedVersion(name string) ([]string, []string, bool)
	AddCveDate(name string) (time.Time, time.Time, bool)

	// Unload runs right after the Updater finished calling AddMetadata for every vulnerabilities.
	Unload()

	// Clean deletes any allocated resources.
	// It is invoked when Clair stops.
	Clean()
}

// RegisterFetcher makes a Fetcher available by the provided name.
// If Register is called twice with the same name or if driver is nil,
// it panics.
func RegisterMetadataFetcher(name string, f MetadataFetcher) {
	if name == "" {
		panic("updater: could not register a MetadataFetcher with an empty name")
	}

	if f == nil {
		panic("updater: could not register a nil MetadataFetcher")
	}

	if _, dup := fetchers[name]; dup {
		panic("updater: RegisterMetadataFetcher called twice for " + name)
	}

	metadataFetchers[name] = f
}
