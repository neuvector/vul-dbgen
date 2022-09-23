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

func parseSecDB(body []byte, url string) ([]updater.Vulnerability, error) {
	var data secDBData
	if err := json.Unmarshal(body, &data); err != nil {
		log.WithError(err).WithFields(log.Fields{"url": url}).Warn("Failed to unmarshal alpine db")
		return nil, err
	}

	var vulns []updater.Vulnerability
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

				var vuln updater.Vulnerability
				vuln.Name = cveName
				vuln.Link = cveURLPrefix + cveName

				featureVersion := updater.FeatureVersion{
					Feature: updater.Feature{
						Namespace: "alpine:" + data.DistroVersion[1:],
						Name:      pkg.Pkg.Name,
					},
					Version: ver,
				}
				vuln.FixedIn = append(vuln.FixedIn, featureVersion)

				vulns = append(vulns, vuln)
			}
		}
	}

	return vulns, nil
}

func (u *AlpineFetcher) downloadSecDB(url string) ([]updater.Vulnerability, error) {
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

	vulsMap := make(map[string]updater.Vulnerability)
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

/*
func correctVulRecord(vul *updater.Vulnerability) {
	if vul.Name == "CVE-2020-1967" {
		for i, _ := range vul.FixedIn {
			vul.FixedIn[i].MinVer, _ = common.NewVersion("1.1.1d")
		}
	}
}

func (u *AlpineFetcher) fromAports() ([]updater.Vulnerability, error) {
	branches, err := u.pullAports()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("pull aports fail")
		return nil, err
	}
	var results []updater.Vulnerability
	for _, branch := range branches {
		if !strings.Contains(branch, "3.") || !strings.HasSuffix(branch, "-stable") {
			continue
		}

		branch = strings.TrimSpace(branch)
		if err = u.checkout(branch); err != nil {
			log.WithFields(log.Fields{"error": err, "branch": branch}).Error("checkout branch fail")
			return nil, err
		}
		branch = strings.TrimLeft(branch, "origin/")
		osVersion := strings.TrimRight(branch, "-stable")
		filepath.Walk(u.aportsLocalPath, func(path string, info os.FileInfo, err error) error {
			if info == nil || info.IsDir() || !strings.HasSuffix(path, "APKBUILD") || !strings.Contains(path, "/main/") {
				return nil
			}
			if name := getPkgName(path); name != "" {
				vuls := getSecfixes(name, path, osVersion)
				results = append(results, vuls...)
			}
			return nil
		})
	}
	return results, nil
}

func getPkgName(path string) string {
	if a := strings.Index(path, "/main/"); a > 0 {
		path = path[a+6:]
		return strings.TrimRight(path, "/APKBUILD")
	}
	return ""
}

//# secfixes:
//#   1.1.1b-r1:
//#     - CVE-2019-1543
//#   1.1.1a-r0:
//#     - CVE-2018-0734
//#     - CVE-2018-0735
func getSecfixes(pkg, path, osVer string) []updater.Vulnerability {
	dat, err := ioutil.ReadFile(path)
	if err != nil {
		return nil
	}
	scanner := bufio.NewScanner(strings.NewReader(string(dat)))
	var fixedVer, cveName string
	secfixes := false
	var vuls []updater.Vulnerability
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "# secfixes:") {
			secfixes = true
		} else if secfixes {
			if !strings.HasPrefix(line, "#") {
				return vuls
			}
			line = strings.TrimLeft(line, "#")
			line = strings.TrimSpace(line)
			if a := strings.Index(line, ":"); a > 0 {
				fixedVer = line[:a]
				fixedVer = strings.TrimLeft(fixedVer, "-")
				fixedVer = strings.TrimSpace(fixedVer)
			} else if strings.HasPrefix(line, "-") {
				cveName = strings.TrimLeft(line, "-")
				cveName = strings.TrimSpace(cveName)
				if vs := generatePkg(pkg, cveName, osVer, fixedVer); vs != nil {
					vuls = append(vuls, vs...)
				}
			}
		}
	}
	return vuls
}

func generatePkg(pkg, cveName, osVer, fixedVer string) []updater.Vulnerability {
	cves := strings.Split(cveName, " ")
	var vulns []updater.Vulnerability
	for _, cve := range cves {
		cve = strings.TrimSpace(cve)

		if !cveRegex.MatchString(cve) {
			log.WithField("cve", cve).Warn("Unknown CVE name format")
			continue
		}
		if year, err := common.ParseYear(cve[4:]); err != nil {
			log.WithField("cve", cve).Warn("Unable to parse year from CVE name")
			continue
		} else if year < common.FirstYear {
			continue
		}

		var vuln updater.Vulnerability
		vuln.Name = cve
		vuln.Link = cveURLPrefix + cve

		ver, err := common.NewVersion(fixedVer)
		if err != nil {
			log.WithFields(log.Fields{"err": err, "version": fixedVer, "cve": cve}).Warn("invalid version")
			continue
		}
		featureVersion := updater.FeatureVersion{
			Feature: updater.Feature{
				Namespace: "alpine:" + osVer,
				Name:      pkg,
			},
			Version: ver,
		}
		vuln.FixedIn = append(vuln.FixedIn, featureVersion)
		vulns = append(vulns, vuln)
	}
	return vulns
}

func (u *AlpineFetcher) pullAports() (commit []string, err error) {
	// If the repository doesn't exist, clone it.
	if u.aportsLocalPath, err = ioutil.TempDir(os.TempDir(), "alpine-aports"); err != nil {
		return nil, fmt.Errorf("something went wrong when interacting with the fs")
	}

	cmd := exec.Command("git", "clone", aportsGitURL, ".")
	cmd.Dir = u.aportsLocalPath
	if out, err := cmd.CombinedOutput(); err != nil {
		u.Clean()
		log.WithError(err).WithField("output", string(out)).Error("could not pull alpine-aports repository")
		return nil, fmt.Errorf("could not download requested resource")
	}

	cmd = exec.Command("git", "branch", "--remote")
	cmd.Dir = u.aportsLocalPath
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.WithFields(log.Fields{"err": err, "out": string(out)}).Error("something went wrong when interacting with git")
		return nil, err
	}

	commit = strings.Split(strings.TrimSpace(string(out)), "\n")
	return
}

func (u *AlpineFetcher) checkout(branch string) error {
	cmd := exec.Command("git", "checkout", "-b", branch)
	cmd.Dir = u.aportsLocalPath
	return cmd.Run()
}
*/
