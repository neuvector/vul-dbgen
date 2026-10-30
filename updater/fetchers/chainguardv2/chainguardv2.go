package chainguardv2

import (
	"archive/zip"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/vul-dbgen/common"
)

const (
	chainguardOSVZipPath = "chainguard/osv-v2.zip"
	advisoryURLPrefix    = "https://advisories.cgr.dev/chainguard/v2/osv/"
	advisoryURLSuffix    = ".json"
	cveURLPrefix         = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="
	chainguardNamespace  = "chainguard"
	wolfiNamespace       = "wolfi"
)

type featureKey struct {
	Name    string
	Version string
}

// FetchVulnerabilities fetches and parses vulnerabilities from the Chainguard OSV v2 feed, filtering by the specified ecosystem and namespace.
// Reference: https://github.com/chainguard-dev/vulnerability-scanner-support/blob/main/docs/osv_v2_feed.md
func FetchVulnerabilities(targetEcosystem, targetNamespace string) ([]common.Vulnerability, error) {
	namespaceName := targetNamespace
	if i := strings.IndexByte(targetNamespace, ':'); i >= 0 {
		namespaceName = targetNamespace[:i]
	}

	switch namespaceName {
	case chainguardNamespace, wolfiNamespace:
	default:
		return nil, fmt.Errorf("unsupported namespace: %s", targetNamespace)
	}

	dataFile := common.CVESourceRoot + chainguardOSVZipPath
	zipReader, err := zip.OpenReader(dataFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open Chainguard OSV v2 zip file %s: %w", dataFile, err)
	}
	defer zipReader.Close()

	var vulnerabilities []common.Vulnerability
	for _, file := range zipReader.File {
		body, err := loadOSVFeedEntry(file)
		if err != nil {
			log.WithFields(log.Fields{
				"ecosystem": targetEcosystem,
				"file":      file.Name,
				"error":     err,
			}).Warn("Failed to read Chainguard OSV v2 advisory")
			continue
		}

		vulns, err := parseAdvisory(body, targetEcosystem, targetNamespace)
		if err != nil {
			log.WithFields(log.Fields{
				"ecosystem": targetEcosystem,
				"file":      file.Name,
				"error":     err,
			}).Warn("Failed to parse Chainguard OSV v2 advisory")
			continue
		}
		if len(vulns) > 0 {
			vulnerabilities = append(vulnerabilities, vulns...)
		}
	}

	return vulnerabilities, nil
}

func loadOSVFeedEntry(feedEntry *zip.File) ([]byte, error) {
	file, err := feedEntry.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", feedEntry.Name, err)
	}
	defer file.Close()

	body, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", feedEntry.Name, err)
	}
	return body, nil
}

func extractCVEs(upstream []string) []string {
	cves := make([]string, 0, len(upstream))
	existCVE := make(map[string]struct{}, len(upstream))
	for _, item := range upstream {
		if !strings.HasPrefix(item, "CVE-") {
			continue
		}
		if _, ok := existCVE[item]; ok {
			continue
		}
		cves = append(cves, item)
		existCVE[item] = struct{}{}
	}
	return cves
}

func extractFixedVersions(ranges []*osvschema.Range) []string {
	fixedVersions := make([]string, 0)
	existFixedVersion := make(map[string]struct{})

	for _, r := range ranges {
		if r.Type != osvschema.Range_ECOSYSTEM {
			continue
		}
		for _, event := range r.Events {
			if event.Fixed == "" {
				continue
			}
			if _, ok := existFixedVersion[event.Fixed]; ok {
				continue
			}
			fixedVersions = append(fixedVersions, event.Fixed)
			existFixedVersion[event.Fixed] = struct{}{}
		}
	}

	return fixedVersions
}

func parseAdvisory(body []byte, targetEcosystem, targetNamespace string) ([]common.Vulnerability, error) {
	var adv osvschema.Vulnerability
	if err := protojson.Unmarshal(body, &adv); err != nil {
		return nil, err
	}

	// Keeps CVE only.
	cves := extractCVEs(adv.Upstream)
	if len(cves) == 0 {
		return nil, nil
	}
	var published, modified time.Time
	if adv.Published != nil {
		published = adv.Published.AsTime()
	}
	if adv.Modified != nil {
		modified = adv.Modified.AsTime()
	}

	advisoryLink := advisoryURLPrefix + adv.Id + advisoryURLSuffix

	vulnMap := make(map[string]*common.Vulnerability, len(cves))
	existFeatures := make(map[string]map[featureKey]struct{}, len(cves))
	for _, cve := range cves {
		link := cveURLPrefix + cve
		if link == cveURLPrefix {
			link = advisoryLink
		}
		vulnMap[cve] = &common.Vulnerability{
			Name:        cve,
			Link:        link,
			IssuedDate:  published,
			LastModDate: modified,
			FixedIn:     make([]common.FeatureVersion, 0),
		}
		existFeatures[cve] = make(map[featureKey]struct{})
	}

	for _, affected := range adv.Affected {
		if affected.Package.Ecosystem != targetEcosystem {
			continue
		}

		for _, fixedVersion := range extractFixedVersions(affected.Ranges) {
			ver, err := common.NewVersion(fixedVersion)
			if err != nil {
				log.WithFields(log.Fields{
					"ecosystem": targetEcosystem,
					"package":   affected.Package.Name,
					"version":   fixedVersion,
					"advisory":  adv.Id,
					"error":     err,
				}).Warn("Failed to parse fixed version from Chainguard OSV v2 advisory")
				continue
			}

			feature := common.FeatureVersion{
				Feature: common.Feature{
					Namespace: targetNamespace,
					Name:      affected.Package.Name,
				},
				Version: ver,
			}

			key := featureKey{Name: affected.Package.Name, Version: fixedVersion}
			for _, cve := range cves {
				if _, ok := existFeatures[cve][key]; ok {
					continue
				}
				vulnMap[cve].FixedIn = append(vulnMap[cve].FixedIn, feature)
				existFeatures[cve][key] = struct{}{}
			}
		}
	}

	vulnerabilities := make([]common.Vulnerability, 0, len(vulnMap))
	for _, cve := range cves {
		if len(vulnMap[cve].FixedIn) == 0 {
			continue
		}
		vulnerabilities = append(vulnerabilities, *vulnMap[cve])
	}

	return vulnerabilities, nil
}
