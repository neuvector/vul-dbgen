package alpine

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/vul-dbgen/common"
	"github.com/vul-dbgen/updater"
)

const (
	minorVerMin  = 2
	minorVerMax  = 20
	secdbURL     = "https://secdb.alpinelinux.org"
	updaterFlag  = "alpine-secdbUpdater"
	cveURLPrefix = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="
)
const (
	aportsGitURL = "git://git.alpinelinux.org/aports"
)

var cveRegex = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

type AlpineFetcher struct {
	repositoryLocalPath string
	// aportsLocalPath     string
}

type secDBData struct {
	Archs         []string `json:"archs"`
	DistroVersion string   `json:"distroversion"`
	Packages      []struct {
		Pkg struct {
			Name     string                     `json:"name"`
			SecFixes map[string]json.RawMessage `json:"secfixes"`
		} `json:"pkg"`
	} `json:"packages"`
}

func init() {
	updater.RegisterFetcher("alpine", &AlpineFetcher{})
}

var cveDescRegex = regexp.MustCompile(`<p data-testid="vuln-description">(.*)</p>`)
var cveSeverRegex = regexp.MustCompile(`<span data-testid="vuln-cvssv2-base-score-severity">([A-Z]*)</span>`)

func parseSecDB(body []byte, url string) ([]common.Vulnerability, error) {
	var data secDBData
	if err := json.Unmarshal(body, &data); err != nil {
		log.WithError(err).WithFields(log.Fields{"url": url}).Warn("Failed to unmarshal alpine db")
		return nil, err
	}

	var vulns []common.Vulnerability
	for _, pkg := range data.Packages {
		for version, raw := range pkg.Pkg.SecFixes {
			ver, err := common.NewVersion(version)
			if err != nil {
				log.WithError(err).WithField("version", version).Warn("Failed to parse package version. skipping")
				continue
			}

			/* to handle case like this
			    {
			       "pkg": {
			           "secfixes": {
			               "7.1.0-r2": [
			                   "CVE-2017-17439"
			               ],
			               "7.1.0-r1": [
			                   "CVE-2017-11103"
			               ],
			               "7.4.0-r0": {}
			           },
			           "name": "heimdal"
			       }
			   },
			*/
			var cves []string
			if err = json.Unmarshal(raw, &cves); err != nil {
				continue
			}

			for _, cveName := range cves {
				if cveName == "CVE-2017-3738" && version == "1.0.2o-r0" {
					log.WithField("version", version).Debug("skip the redundant version")
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
						Namespace: "alpine:" + data.DistroVersion[1:],
						Name:      pkg.Pkg.Name,
					},
					Version: ver,
				}
				vuln.FixedIn = append(vuln.FixedIn, featureVersion)

				vulns = append(vulns, vuln)

				common.DEBUG_VULN(&vuln, "alpine")
			}
		}
	}

	return vulns, nil
}

func (u *AlpineFetcher) downloadSecDB(url string) ([]common.Vulnerability, error) {
	r, err := http.Get(url)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{"url": url}).Error("Failed to download alpine db")
		return nil, err
	}

	body, _ := ioutil.ReadAll(r.Body)
	defer r.Body.Close()

	return parseSecDB(body, url)
}

func (u *AlpineFetcher) downloadSecDBNamespaces() ([]string, error) {
	r, err := http.Get(secdbURL)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{"url": secdbURL}).Error("Failed to download alpine db")
		return nil, err
	}

	defer r.Body.Close()
	body, _ := ioutil.ReadAll(r.Body)

	nss := make([]string, 0)

	// locate folder from the list
	var nsRegexp = regexp.MustCompile(`<a href="v.*/">(.*)/</a>.*-`)
	matches := nsRegexp.FindAllStringSubmatch(string(body[:]), -1)
	for _, m := range matches {
		nss = append(nss, m[1])
	}

	return nss, nil
}

func (u *AlpineFetcher) FetchUpdate() (resp updater.FetcherResponse, err error) {
	log.WithField("package", "Alpine").Info("Start fetching vulnerabilities")

	// Download from secdb
	if nss, err := u.downloadSecDBNamespaces(); err == nil {
		for _, ns := range nss {
			log.WithFields(log.Fields{"namespace": ns}).Debug()

			if vulns, err := u.downloadSecDB(fmt.Sprintf("%s/%s/main.json", secdbURL, ns)); err == nil {
				resp.Vulnerabilities = append(resp.Vulnerabilities, vulns...)
			}
			if vulns, err := u.downloadSecDB(fmt.Sprintf("%s/%s/community.json", secdbURL, ns)); err == nil {
				resp.Vulnerabilities = append(resp.Vulnerabilities, vulns...)
			}
		}
	}

	vulsMap := make(map[string]common.Vulnerability)
	for _, vul := range resp.Vulnerabilities {
		key := fmt.Sprintf("%s:%s", vul.FixedIn[0].Feature.Namespace, vul.Name)
		vulsMap[key] = vul
	}

	// Download from aport
	/*
		if vuls, err := u.fromAports(); err == nil {
			for _, vul := range vuls {
				key := fmt.Sprintf("%s:%s", vul.FixedIn[0].Feature.Namespace, vul.Name)
				if _, ok := vulsMap[key]; !ok {
					correctVulRecord(&vul)
					resp.Vulnerabilities = append(resp.Vulnerabilities, vul)
					//log.WithFields(log.Fields{"CVE": vul.Name}).Debug("add cve")
				}
			}
		} else {
			return resp, err
		}
	*/

	log.WithFields(log.Fields{"Vulnerabilities": len(resp.Vulnerabilities)}).Info("fetching alpine done")
	return resp, nil
}

func (u *AlpineFetcher) Clean() {
	if u.repositoryLocalPath != "" {
		os.RemoveAll(u.repositoryLocalPath)
	}

	// if u.aportsLocalPath != "" {
	// 	os.RemoveAll(u.aportsLocalPath)
	// }
}
