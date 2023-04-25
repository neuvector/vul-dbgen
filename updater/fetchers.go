package updater

import (
	"time"

	"github.com/vul-dbgen/common"
)

type NetInterface interface {
	DownloadHTMLPage(url string) (string, string, error)
}

var fetchers = make(map[string]Fetcher)
var appFetchers = make(map[string]AppFetcher)
var rawFetchers = make(map[string]RawFetcher)

type Fetcher interface {
	FetchUpdate() (FetcherResponse, error)
	Clean()
}

type AppFetcher interface {
	FetchUpdate(metadataFetchers map[string]MetadataFetcher) (AppFetcherResponse, error)
	Clean()
}

type RawFetcher interface {
	FetchUpdate() (RawFetcherResponse, error)
	Clean()
}

type MetadataMap map[string]interface{}

type Feature struct {
	Name      string
	Namespace string
}

type FeatureVersion struct {
	Name    string
	Feature Feature
	Version common.Version
	MinVer  common.Version
}

type CVSS struct {
	Vectors string
	Score   float64
}

type CVE struct {
	Name   string
	CVSSv2 CVSS
	CVSSv3 CVSS
}

type Vulnerability struct {
	Name      string
	Namespace string

	Description string
	Link        string
	Severity    common.Priority
	CVEs        []CVE
	IssuedDate  time.Time
	LastModDate time.Time

	Metadata MetadataMap

	FixedIn    []FeatureVersion
	CPEs       []string
	FeedRating string
}

type FetcherResponse struct {
	Vulnerabilities []Vulnerability
}

type AppFetcherResponse struct {
	Vulnerabilities []common.AppModuleVul
}

type RawFetcherResponse struct {
	Name string
	Raw  []byte
}

// RegisterFetcher makes a Fetcher available by the provided name.
// If Register is called twice with the same name or if driver is nil,
// it panics.
func RegisterFetcher(name string, f Fetcher) {
	if name == "" {
		panic("updater: could not register a Fetcher with an empty name")
	}

	if f == nil {
		panic("updater: could not register a nil Fetcher")
	}

	if _, dup := fetchers[name]; dup {
		panic("updater: RegisterFetcher called twice for " + name)
	}

	fetchers[name] = f
}

func RegisterAppFetcher(name string, f AppFetcher) {
	if name == "" {
		panic("updater: could not register a Fetcher with an empty name")
	}

	if f == nil {
		panic("updater: could not register a nil Fetcher")
	}

	if _, dup := appFetchers[name]; dup {
		panic("updater: RegisterFetcher called twice for " + name)
	}

	appFetchers[name] = f
}

func RegisterRawFetcher(name string, f RawFetcher) {
	if name == "" {
		panic("updater: could not register a Fetcher with an empty name")
	}

	if f == nil {
		panic("updater: could not register a nil Fetcher")
	}

	if _, dup := rawFetchers[name]; dup {
		panic("updater: RegisterFetcher called twice for " + name)
	}

	rawFetchers[name] = f
}
