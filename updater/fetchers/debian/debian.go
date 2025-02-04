// Copyright 2015 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package debian

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/vul-dbgen/common"
	"github.com/vul-dbgen/updater"
)

const (
	debianURL       = "https://security-tracker.debian.org/tracker/data/json"
	debianURLPrefix = "https://security-tracker.debian.org/tracker"
	debianJsonFile  = "debian/debian.json"
	maxRetryTimes   = 5
)

var additionalDebianFiles = []string{
	"debian/debian-stretch.json", //Partial dataset for debian 9, sourced via wayback machine snapshot of https://security-tracker.debian.org/tracker/data/json
	"debian/debian-buster.json",  //Dataset for debian 10
}

type jsonData map[string]map[string]jsonVuln

type jsonVuln struct {
	Description string             `json:"description"`
	Releases    map[string]jsonRel `json:"releases"`
}

type jsonRel struct {
	FixedVersion string `json:"fixed_version"`
	Status       string `json:"status"`
	Urgency      string `json:"urgency"`
}

// DebianFetcher implements updater.Fetcher for the Debian Security Tracker
// (https://security-tracker.debian.org).
type DebianFetcher struct{}

func init() {
	updater.RegisterFetcher("debian", &DebianFetcher{})
}

// FetchUpdate fetches vulnerability updates from the Debian Security Tracker.
func (fetcher *DebianFetcher) FetchUpdate() (resp updater.FetcherResponse, err error) {
	log.Info("fetching Debian vulnerabilities")

	var reader io.Reader

	jsonFile := fmt.Sprintf("%s%s", common.CVESourceRoot, debianJsonFile)
	if f, err := os.Open(jsonFile); err == nil {
		log.Debug("Use local Debian database")

		defer f.Close()
		reader = bufio.NewReader(f)
	} else {
		log.WithFields(log.Fields{"error": err}).Error("Download Debian database from Internet")

		var r *http.Response
		// Download JSON.
		retry := 0
		for retry <= maxRetryTimes {
			r, err = http.Get(debianURL)
			if err == nil {
				break
			}
			if err != nil && retry >= maxRetryTimes {
				log.Errorf("could not download Debian's update: %s", err)
				return resp, common.ErrCouldNotDownload
			}
			retry++
			log.WithFields(log.Fields{"retry": retry, "error": err}).Debug("Download debian vulnerabilities")
		}

		defer r.Body.Close()
		reader = r.Body
	}

	// Parse the JSON.
	resp, err = buildResponse(reader)
	if err != nil {
		return resp, err
	}
	//Add response to map of full results
	responseVulnMap := map[string]common.Vulnerability{}
	for _, vuln := range resp.Vulnerabilities {
		responseVulnMap[vuln.Name] = vuln
	}

	for _, file := range additionalDebianFiles {
		//Open json
		jsonFile := fmt.Sprintf("%s%s", common.CVESourceRoot, file)
		if f, err := os.Open(jsonFile); err == nil {
			log.WithFields(log.Fields{"file": file}).Debug("Using local Debian source")
			defer f.Close()
			reader = bufio.NewReader(f)
		} else {
			log.WithFields(log.Fields{"error": err, "file": file}).Error("Error opening file")
		}
		resp2, err := buildResponse(reader)
		if err != nil {
			return resp2, err
		}
		//Add response to map of full results
		for _, vuln := range resp2.Vulnerabilities {
			if val, ok := responseVulnMap[vuln.Name]; ok {
				//If cve exists, combine both fixedIn lists
				val.FixedIn = append(val.FixedIn, vuln.FixedIn...)
				responseVulnMap[vuln.Name] = val
			} else {
				responseVulnMap[vuln.Name] = vuln
			}
		}
	}

	fullVulns := []common.Vulnerability{}
	for _, vuln := range responseVulnMap {
		fullVulns = append(fullVulns, vuln)
	}
	resp.Vulnerabilities = fullVulns

	log.WithFields(log.Fields{"Vulnerabilities": len(resp.Vulnerabilities)}).Info("fetching Debian done")
	return resp, nil
}

func buildResponse(jsonReader io.Reader) (resp updater.FetcherResponse, err error) {
	// Unmarshal JSON.
	var data jsonData
	err = json.NewDecoder(jsonReader).Decode(&data)
	if err != nil {
		log.Errorf("could not unmarshal Debian's JSON: %s", err)
		return resp, common.ErrCouldNotParse
	}

	// Extract vulnerability data from Debian's JSON schema.
	resp.Vulnerabilities, _ = parseDebianJSON(&data)
	if len(resp.Vulnerabilities) == 0 {
		log.Error("Debian update CVE FAIL")
		return resp, fmt.Errorf("Debian update CVE FAIL")
	}

	return resp, nil
}

func parseDebianJSON(data *jsonData) (vulnerabilities []common.Vulnerability, unknownReleases map[string]struct{}) {
	mvulnerabilities := make(map[string]*common.Vulnerability)
	unknownReleases = make(map[string]struct{})

	for pkgName, pkgNode := range *data {
		for vulnName, vulnNode := range pkgNode {
			for releaseName, releaseNode := range vulnNode.Releases {
				// Attempt to detect the release number.
				if _, isReleaseKnown := common.DebianReleasesMapping[releaseName]; !isReleaseKnown {
					unknownReleases[releaseName] = struct{}{}
					continue
				}

				// Skip if the status is not determined or the vulnerability is a temporary one.
				if releaseNode.Status == "undetermined" {
					continue
				} else if !strings.HasPrefix(vulnName, "CVE-") {
					continue
				} else if year, err := common.ParseYear(vulnName[4:]); err != nil {
					log.WithField("cve", vulnName).Warn("Unable to parse year from CVE name")
					continue
				} else if year < common.FirstYear {
					continue
				}

				// Get or create the vulnerability.
				vulnerability, vulnerabilityAlreadyExists := mvulnerabilities[vulnName]
				if !vulnerabilityAlreadyExists {
					vulnerability = &common.Vulnerability{
						Name:        vulnName,
						Link:        strings.Join([]string{debianURLPrefix, "/", vulnName}, ""),
						Severity:    common.Unknown,
						Description: vulnNode.Description,
					}
				}

				// Set the priority of the vulnerability.
				// In the JSON, a vulnerability has one urgency per package it affects.
				// The highest urgency should be the one set.
				urgency := urgencyToSeverity(releaseNode.Urgency)
				vulnerability.FeedRating = releaseNode.Urgency
				if urgency.Compare(vulnerability.Severity) > 0 {
					vulnerability.Severity = urgency
				}

				// Determine the version of the package the vulnerability affects.
				var version common.Version
				var err error
				if releaseNode.FixedVersion == "0" {
					// This means that the package is not affected by this vulnerability.
					version = common.MinVersion
				} else if releaseNode.Status == "open" {
					// Open means that the package is currently vulnerable in the latest
					// version of this Debian release.
					version = common.MaxVersion
				} else if releaseNode.Status == "resolved" {
					// Resolved means that the vulnerability has been fixed in
					// "fixed_version" (if affected).
					version, err = common.NewVersion(releaseNode.FixedVersion)
					if err != nil {
						log.Warningf("could not parse package version '%s': %s. skipping", releaseNode.FixedVersion, err.Error())
						continue
					}
				}

				// Create and add the feature version.
				pkg := common.FeatureVersion{
					Feature: common.Feature{
						Name:      pkgName,
						Namespace: "debian:" + common.DebianReleasesMapping[releaseName],
					},
					Version: version,
				}
				vulnerability.FixedIn = append(vulnerability.FixedIn, pkg)

				// Store the vulnerability.
				mvulnerabilities[vulnName] = vulnerability

			}
		}
	}

	// Convert the vulnerabilities map to a slice
	for _, v := range mvulnerabilities {
		vulnerabilities = append(vulnerabilities, *v)
	}

	return
}

func urgencyToSeverity(urgency string) common.Priority {
	switch urgency {
	case "not yet assigned":
		return common.Unknown

	case "end-of-life":
		fallthrough
	case "unimportant":
		return common.Negligible

	case "low":
		fallthrough
	case "low*":
		fallthrough
	case "low**":
		return common.Low

	case "medium":
		fallthrough
	case "medium*":
		fallthrough
	case "medium**":
		return common.Medium

	case "high":
		fallthrough
	case "high*":
		fallthrough
	case "high**":
		return common.High

	default:
		log.Warningf("could not determine vulnerability priority from: %s", urgency)
		return common.Unknown
	}
}

// Clean deletes any allocated resources.
func (fetcher *DebianFetcher) Clean() {}
