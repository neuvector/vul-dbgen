package photon

import (
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/vul-dbgen/common"
	"github.com/vul-dbgen/updater"
)

var (
	photonFiles = []string{
		"photon/com.vmware.phsa-photon1.xml.gz",
		"photon/com.vmware.phsa-photon2.xml.gz",
		"photon/com.vmware.phsa-photon3.xml.gz",
		"photon/com.vmware.phsa-photon4.xml.gz",
		"photon/com.vmware.phsa-photon5.xml.gz",
	}

	alternatePackageNames = map[string]string{
		"expat": "expat-libs",
	}

	cveRegexp      = regexp.MustCompile(`\bCVE-\d{4}-\d+\b`)
	photonPlatform = regexp.MustCompile(`(?i)^Photon\s+(\d+)$`)
)

type PhotonFetcher struct{}

type photonOVAL struct {
	Definitions []photonDefinition `xml:"definitions>definition"`
	Tests       []photonTest       `xml:"tests>rpminfo_test"`
	Objects     []photonObject     `xml:"objects>rpminfo_object"`
	States      []photonState      `xml:"states>rpminfo_state"`
}

type photonDefinition struct {
	Metadata photonMetadata `xml:"metadata"`
	Criteria photonCriteria `xml:"criteria"`
}

type photonMetadata struct {
	Platform    string            `xml:"affected>platform"`
	References  []photonReference `xml:"reference"`
	Description string            `xml:"description"`
	Advisory    photonAdvisory    `xml:"advisory"`
}

type photonReference struct {
	Source string `xml:"source,attr"`
	ID     string `xml:"ref_id,attr"`
	URL    string `xml:"ref_url,attr"`
}

type photonAdvisory struct {
	Severity string         `xml:"severity"`
	CVEs     []string       `xml:"cve"`
	Issued   photonOVALDate `xml:"issued"`
	Updated  photonOVALDate `xml:"updated"`
}

type photonOVALDate struct {
	Date string `xml:"date,attr"`
}

type photonCriteria struct {
	Criterias  []photonCriteria  `xml:"criteria"`
	Criterions []photonCriterion `xml:"criterion"`
}

type photonCriterion struct {
	TestRef string `xml:"test_ref,attr"`
}

type photonTest struct {
	ID     string          `xml:"id,attr"`
	Object photonObjectRef `xml:"object"`
	State  photonStateRef  `xml:"state"`
}

type photonObjectRef struct {
	Reference string `xml:"object_ref,attr"`
}

type photonStateRef struct {
	Reference string `xml:"state_ref,attr"`
}

type photonObject struct {
	ID   string `xml:"id,attr"`
	Name string `xml:"name"`
}

type photonState struct {
	ID  string    `xml:"id,attr"`
	EVR photonEVR `xml:"evr"`
}

type photonEVR struct {
	Operation string `xml:"operation,attr"`
	Value     string `xml:",chardata"`
}

func init() {
	updater.RegisterFetcher("photon", &PhotonFetcher{})
}

func (f *PhotonFetcher) FetchUpdate() (resp updater.FetcherResponse, err error) {
	log.WithField("package", "Photon").Info("Start fetching vulnerabilities")

	vulns, err := f.fetchLocal(photonFiles)
	if err != nil {
		return resp, err
	}
	resp.Vulnerabilities = append(resp.Vulnerabilities, vulns...)

	log.WithFields(log.Fields{"Vulnerabilities": len(resp.Vulnerabilities)}).Info("fetching photon done")
	return resp, nil
}

func (f *PhotonFetcher) fetchLocal(files []string) ([]common.Vulnerability, error) {
	var results []common.Vulnerability
	for _, name := range files {
		dataFile := fmt.Sprintf("%s%s", common.CVESourceRoot, name)
		file, err := os.Open(dataFile)
		if err != nil {
			log.WithField("file", dataFile).Error("Cannot find local database")
			return results, err
		}

		gzr, err := gzip.NewReader(file)
		if err != nil {
			file.Close()
			log.WithField("file", dataFile).Error("Failed to create feed reader")
			return results, err
		}

		vulns, parseErr := parsePhotonOVAL(gzr)
		gzr.Close()
		file.Close()
		if parseErr != nil {
			return results, parseErr
		}
		results = append(results, vulns...)
	}
	return results, nil
}

func parsePhotonOVAL(reader io.Reader) ([]common.Vulnerability, error) {
	var oval photonOVAL
	if err := xml.NewDecoder(reader).Decode(&oval); err != nil {
		return nil, fmt.Errorf("decode Photon OVAL: %w", err)
	}

	tests := make(map[string]photonTest, len(oval.Tests))
	for _, test := range oval.Tests {
		tests[test.ID] = test
	}
	objects := make(map[string]photonObject, len(oval.Objects))
	for _, object := range oval.Objects {
		objects[object.ID] = object
	}
	states := make(map[string]photonState, len(oval.States))
	for _, state := range oval.States {
		states[state.ID] = state
	}

	var vulnerabilities []common.Vulnerability
	for _, definition := range oval.Definitions {
		namespace, ok := photonNamespace(definition.Metadata.Platform)
		if !ok {
			log.WithField("platform", definition.Metadata.Platform).Warn("Skipping Photon definition with unknown platform")
			continue
		}

		fixedIn := photonFixedIn(definition.Criteria, namespace, tests, objects, states)
		if len(fixedIn) == 0 {
			continue
		}

		for _, cve := range photonCVEs(definition.Metadata) {
			vulnerabilities = append(vulnerabilities, common.Vulnerability{
				Name:        cve,
				Namespace:   namespace,
				Description: definition.Metadata.Description,
				Link:        photonLink(definition.Metadata),
				Severity:    photonSeverity(definition.Metadata.Advisory.Severity),
				IssuedDate:  photonDate(definition.Metadata.Advisory.Issued.Date),
				LastModDate: photonDate(definition.Metadata.Advisory.Updated.Date),
				CVEs:        []common.CVE{{Name: cve}},
				FixedIn:     fixedIn,
				CPEs:        []string{},
			})
		}
	}

	return vulnerabilities, nil
}

func photonNamespace(platform string) (string, bool) {
	match := photonPlatform.FindStringSubmatch(strings.TrimSpace(platform))
	if len(match) != 2 {
		return "", false
	}
	version, err := strconv.Atoi(match[1])
	if err != nil {
		return "", false
	}
	return fmt.Sprintf("photon:%d", version), true
}

func photonCVEs(metadata photonMetadata) []string {
	seen := make(map[string]struct{})
	var cves []string
	add := func(value string) {
		cve := cveRegexp.FindString(value)
		if cve == "" {
			return
		}
		if _, ok := seen[cve]; ok {
			return
		}
		seen[cve] = struct{}{}
		cves = append(cves, cve)
	}

	for _, cve := range metadata.Advisory.CVEs {
		add(cve)
	}
	for _, reference := range metadata.References {
		if strings.EqualFold(reference.Source, "CVE") {
			add(reference.ID)
		}
	}
	return cves
}

func photonFixedIn(criteria photonCriteria, namespace string, tests map[string]photonTest, objects map[string]photonObject, states map[string]photonState) []common.FeatureVersion {
	var criterions []photonCriterion
	collectPhotonCriterions(criteria, &criterions)

	seen := make(map[string]struct{})
	var fixedIn []common.FeatureVersion
	for _, criterion := range criterions {
		test, ok := tests[criterion.TestRef]
		if !ok {
			continue
		}
		state, ok := states[test.State.Reference]
		if !ok || !strings.HasPrefix(strings.ToLower(state.EVR.Operation), "less than") {
			continue
		}
		versionString := strings.TrimSpace(state.EVR.Value)
		if versionString == "" {
			continue
		}
		if versionString == "N/A" || versionString == "NA" {
			versionString = common.MaxVersion.String()
		}
		version, err := common.NewVersion(versionString)
		if err != nil {
			log.WithFields(log.Fields{"test": criterion.TestRef, "version": versionString, "error": err}).Warn("Skipping Photon package with invalid version")
			continue
		}
		object, ok := objects[test.Object.Reference]
		if !ok || strings.TrimSpace(object.Name) == "" {
			continue
		}

		appendPhotonFeature(&fixedIn, seen, object.Name, namespace, version)
		if alias, ok := alternatePackageNames[object.Name]; ok {
			appendPhotonFeature(&fixedIn, seen, alias, namespace, version)
		}
	}
	return fixedIn
}

func collectPhotonCriterions(criteria photonCriteria, criterions *[]photonCriterion) {
	*criterions = append(*criterions, criteria.Criterions...)
	for _, nested := range criteria.Criterias {
		collectPhotonCriterions(nested, criterions)
	}
}

func appendPhotonFeature(features *[]common.FeatureVersion, seen map[string]struct{}, name, namespace string, version common.Version) {
	key := namespace + ":" + name + ":" + version.String()
	if _, ok := seen[key]; ok {
		return
	}
	seen[key] = struct{}{}
	*features = append(*features, common.FeatureVersion{
		Name: name,
		Feature: common.Feature{
			Name:      name,
			Namespace: namespace,
		},
		Version: version,
	})
}

func photonSeverity(severity string) common.Priority {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "low":
		return common.Low
	case "moderate", "medium":
		return common.Medium
	case "important", "high":
		return common.High
	case "critical":
		return common.Critical
	default:
		return common.Unknown
	}
}

func photonLink(metadata photonMetadata) string {
	for _, reference := range metadata.References {
		if strings.EqualFold(reference.Source, "PHSA") {
			return reference.URL
		}
	}
	for _, reference := range metadata.References {
		if strings.EqualFold(reference.Source, "CVE") {
			return reference.URL
		}
	}
	return ""
}

func photonDate(value string) time.Time {
	date, err := time.Parse("2006-01-02", value)
	if err != nil {
		return time.Time{}
	}
	return date
}

func (f *PhotonFetcher) Clean() {}
