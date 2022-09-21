package updater

import (
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/vul-dbgen/common"
)

const (
	flagName      = "updater/last"
	notesFlagName = "updater/notes"

	CVESourceRoot = "vul-source/"
)

type RawFile struct {
	Name string
	Raw  []byte
}

func init() {
}

func IgnoreSeverity(s common.Priority) bool {
	return s != common.Critical && s != common.High && s != common.Medium /* && s != common.Low */
}

// Update fetches all the vulnerabilities from the registered fetchers, upserts
// them into the database and then sends notifications.
func Update(datastore Datastore) bool {
	log.Info("updating vulnerabilities")

	// Fetch updates.
	status, vulnerabilities, appVuls, rawFiles := fetch(datastore)
	if !status {
		log.WithFields(log.Fields{"status": status}).Error("CVE update FAIL")
		return false
	}

	// Insert vulnerabilities.
	//log.Tracef("inserting %d vulnerabilities for update", len(vulnerabilities))
	err := datastore.InsertVulnerabilities(vulnerabilities, appVuls, rawFiles)
	if err != nil {
		log.Errorf("an error occured when inserting vulnerabilities for update: %s", err)
		return false
	}
	vulnerabilities = nil

	log.Info("update finished")
	return true
}

const cveURLPrefix = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="

func xslateUbuntuUpstream(vuls []Vulnerability) []common.AppModuleVul {
	upstream := make([]common.AppModuleVul, 0)
	for _, v := range vuls {
		if v.Namespace == "ubuntu:upstream" {
			for _, ff := range v.FixedIn {
				mv := common.AppModuleVul{
					VulName:     v.Name,
					ModuleName:  ff.Name,
					Description: v.Description,
					Link:        cveURLPrefix + v.Name,
					Severity:    string(v.Severity),
					AffectedVer: []common.AppModuleVersion{common.AppModuleVersion{OpCode: "lt", Version: ff.Version.String()}},
					FixedVer:    []common.AppModuleVersion{common.AppModuleVersion{OpCode: "gteq", Version: ff.Version.String()}},
				}
				upstream = append(upstream, mv)
			}
		}
	}
	return upstream
}

// fetch get data from the registered fetchers, in parallel.
func fetch(datastore Datastore) (bool, []Vulnerability, []common.AppModuleVul, []RawFile) {
	var vulnerabilities []Vulnerability
	var appVuls []common.AppModuleVul
	var rawFiles []RawFile
	status := true

	// Fetch updates in parallel.
	log.Info("fetching vulnerability updates")
	var responseC = make(chan *FetcherResponse, 0)
	for n, f := range fetchers {
		go func(name string, fetcher Fetcher) {
			response, err := fetcher.FetchUpdate()
			if err != nil {
				log.WithFields(log.Fields{"name": name, "error": err}).Error("Distro CVE update FAIL")
				status = false
				responseC <- nil
				return
			}

			responseC <- &response
		}(n, f)
	}

	// Collect results of updates.
	for i := 0; i < len(fetchers); i++ {
		resp := <-responseC
		if resp != nil {
			vulnerabilities = append(vulnerabilities, doVulnerabilitiesNamespacing(resp.Vulnerabilities)...)
		}
	}

	close(responseC)
	if !status {
		return status, nil, nil, nil
	}

	// --
	vuls, status := addMetadata(datastore, vulnerabilities)
	results := make([]Vulnerability, 0)
	for _, v := range vuls {
		if !IgnoreSeverity(v.Severity) {
			results = append(results, v)
		}
	}

	// app vulnerability, must be done metadata is fetched
	log.Info("fetching app vulnerability updates")
	upstream := xslateUbuntuUpstream(vulnerabilities)
	for name, f := range appFetchers {
		response, err := f.FetchUpdate(metadataFetchers, upstream)
		if err != nil {
			log.WithFields(log.Fields{"name": name, "error": err}).Error("App CVE update FAIL")
			return false, nil, nil, nil
		} else {
			appVuls = append(appVuls, response.Vulnerabilities...)
		}
	}

	log.Info("fetching raw data updates")
	var responseR = make(chan *RawFetcherResponse, 0)
	for n, f := range rawFetchers {
		go func(name string, fetcher RawFetcher) {
			response, err := fetcher.FetchUpdate()
			if err != nil {
				log.WithFields(log.Fields{"name": name, "error": err}).Error("RAW update FAIL")
				status = false
				responseR <- nil
				return
			}

			responseR <- &response
		}(n, f)
	}

	// Collect results of updates.
	for i := 0; i < len(rawFetchers); i++ {
		resp := <-responseR
		if resp != nil {
			rawFiles = append(rawFiles, RawFile{Name: resp.Name, Raw: resp.Raw})
		}
	}

	close(responseR)
	if !status {
		return status, nil, nil, nil
	}

	return status, results, appVuls, rawFiles
}

// Add metadata to the specified vulnerabilities using the registered MetadataFetchers, in parallel.
func addMetadata(datastore Datastore, vulnerabilities []Vulnerability) ([]Vulnerability, bool) {
	status := true
	if len(metadataFetchers) == 0 {
		return vulnerabilities, false
	}

	log.Info("adding metadata to vulnerabilities")

	// Wrap vulnerabilities in VulnerabilityWithLock.
	// It ensures that only one metadata fetcher at a time can modify the Metadata map.
	vulnerabilitiesWithLocks := make([]*VulnerabilityWithLock, 0, len(vulnerabilities))
	for i := 0; i < len(vulnerabilities); i++ {
		vulnerabilitiesWithLocks = append(vulnerabilitiesWithLocks, &VulnerabilityWithLock{
			Vulnerability: &vulnerabilities[i],
		})
	}

	var wg sync.WaitGroup
	wg.Add(len(metadataFetchers))

	for n, f := range metadataFetchers {
		go func(name string, metadataFetcher MetadataFetcher) {
			defer wg.Done()

			// Load the metadata fetcher.
			if err := metadataFetcher.Load(datastore); err != nil {
				log.Errorf("an error occured when loading metadata fetcher '%s': %s.", name, err)
				status = false
				return
			}

			// Add metadata to each vulnerability.
			for _, vulnerability := range vulnerabilitiesWithLocks {
				metadataFetcher.AddMetadata(vulnerability)
			}
		}(n, f)
	}

	wg.Wait()

	return vulnerabilities, status
}

func doVulnerabilitiesNamespacing(vulnerabilities []Vulnerability) []Vulnerability {
	vulnerabilitiesMap := make(map[string]*Vulnerability)

	for _, v := range vulnerabilities {
		featureVersions := v.FixedIn
		v.FixedIn = []FeatureVersion{}

		for _, fv := range featureVersions {
			index := fv.Feature.Namespace + ":" + v.Name

			if vulnerability, ok := vulnerabilitiesMap[index]; !ok {
				newVulnerability := v
				newVulnerability.Namespace = fv.Feature.Namespace
				newVulnerability.FixedIn = []FeatureVersion{fv}

				vulnerabilitiesMap[index] = &newVulnerability
			} else {
				vulnerability.FixedIn = append(vulnerability.FixedIn, fv)
			}
		}
	}

	// Convert map into a slice.
	var response []Vulnerability
	for _, vulnerability := range vulnerabilitiesMap {
		response = append(response, *vulnerability)
	}

	return response
}
