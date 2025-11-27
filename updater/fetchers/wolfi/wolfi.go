package wolfi

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/vul-dbgen/common"
	"github.com/vul-dbgen/updater"
)

const (
	securityURL  = "https://packages.wolfi.dev/os/security.json"
	updaterFlag  = "wolfi-secdbUpdater"
	cveURLPrefix = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="
	// Wolfi uses rolling releases, so we use a generic version identifier
	wolfiVersion = "rolling"
)

var cveRegex = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

type WolfiFetcher struct{}

type secDBData struct {
	APKUrl   string `json:"apkurl"`
	Archs    []string `json:"archs"`
	RepoName string `json:"reponame"`
	URLPrefix string `json:"urlprefix"`
	Packages []struct {
		Pkg struct {
			Name     string                     `json:"name"`
			SecFixes map[string]json.RawMessage `json:"secfixes"`
		} `json:"pkg"`
	} `json:"packages"`
}

func init() {
	updater.RegisterFetcher("wolfi", &WolfiFetcher{})
}

func parseSecDB(body []byte, url string) ([]common.Vulnerability, error) {
	var data secDBData
	if err := json.Unmarshal(body, &data); err != nil {
		log.WithError(err).WithFields(log.Fields{"url": url}).Warn("Failed to unmarshal wolfi db")
		return nil, err
	}

	var vulns []common.Vulnerability
	for _, pkg := range data.Packages {
		for version, raw := range pkg.Pkg.SecFixes {
			// Skip version "0" entries as they represent false positives
			if version == "0" {
				continue
			}

			ver, err := common.NewVersion(version)
			if err != nil {
				log.WithError(err).WithField("version", version).Warn("Failed to parse package version. skipping")
				continue
			}

			var cves []string
			if err = json.Unmarshal(raw, &cves); err != nil {
				continue
			}

			for _, cveName := range cves {
				// Filter out GHSA identifiers, only process CVEs
				if !cveRegex.MatchString(cveName) {
					continue
				}

				if year, err := common.ParseYear(cveName[4:]); err != nil {
					log.WithField("cve", cveName).Warn("Unable to parse year from CVE name")
					continue
				} else if year < common.FirstYear {
					continue
				}

				if s := strings.Index(cveName, " "); s != -1 {
					cveName = cveName[:s]
				}

				var vuln common.Vulnerability
				vuln.Name = cveName
				vuln.Link = cveURLPrefix + cveName

				featureVersion := common.FeatureVersion{
					Feature: common.Feature{
						Namespace: "wolfi:" + wolfiVersion,
						Name:      pkg.Pkg.Name,
					},
					Version: ver,
				}
				vuln.FixedIn = append(vuln.FixedIn, featureVersion)

				vulns = append(vulns, vuln)

				common.DEBUG_VULN(&vuln, "wolfi")
			}
		}
	}

	return vulns, nil
}

func (u *WolfiFetcher) downloadSecDB(url string) ([]common.Vulnerability, error) {
	r, err := http.Get(url)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{"url": url}).Error("Failed to download wolfi db")
		return nil, err
	}

	body, _ := ioutil.ReadAll(r.Body)
	defer r.Body.Close()

	return parseSecDB(body, url)
}

func (u *WolfiFetcher) FetchUpdate() (resp updater.FetcherResponse, err error) {
	log.WithField("package", "Wolfi").Info("Start fetching vulnerabilities")

	// Download security.json
	if vulns, err := u.downloadSecDB(securityURL); err == nil {
		resp.Vulnerabilities = append(resp.Vulnerabilities, vulns...)
	} else {
		return resp, err
	}

	log.WithFields(log.Fields{"Vulnerabilities": len(resp.Vulnerabilities)}).Info("fetching wolfi done")
	return resp, nil
}

func (u *WolfiFetcher) Clean() {
	// No cleanup needed for Wolfi fetcher
}
