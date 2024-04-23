package apps

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/vul-dbgen/common"
)

const (
	openssluri = "https://www.openssl.org/news/vulnerabilities.html"
)

var cveNameRegexp = regexp.MustCompile(`<a href="(.*)" name="CVE-([0-9\-]+)">`)
var fixedVerRegexp = regexp.MustCompile(`Fixed in OpenSSL\s*\n*([0-9a-z\.\-\s]+)`)
var affectedVerRegexp = regexp.MustCompile(`\(Affected\s+([0-9a-z\.\-,\s]+)\s*\)`)
var verRegexp = regexp.MustCompile(`Fixed in OpenSSL\s*\n*([0-9a-z\.\-\s]+).*?\(Affected\s+([0-9a-z\.\-,\s]+)\s*\)`) // ungreedy
var severityRegexp = regexp.MustCompile(`\[([a-zA-Z]+) severity\]`)

// FetchUpdate gets vulnerability updates from the openssl.
func opensslUpdate() error {
	var cveCount int
	log.Info("fetching openssl vulnerabilities")

	r, err := http.Get(openssluri)
	if err != nil {
		log.Errorf("could not download openssl update list: %s", err.Error())
		return err
	}

	body, _ := ioutil.ReadAll(r.Body)
	defer r.Body.Close()

	cves := strings.Split(string(body), "<dt>")
	for id, cve := range cves {
		if id == 0 {
			//skip the first header summary
			continue
		}
		var description, severity, link string
		var cveNumber string
		var modVul common.AppModuleVul

		line := strings.Trim(cve, "\n")
		match := cveNameRegexp.FindAllStringSubmatch(line, -1)
		if len(match) > 0 {
			s := match[0]
			cveNumber = s[2]
			link = s[1]
		} else {
			continue
		}
		if !strings.HasPrefix(cveNumber, "201") {
			continue
		}

		vulName := "CVE-" + cveNumber

		fver, aver, err := getOpensslVulVersion(vulName, line)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error()
			continue
		}

		match = severityRegexp.FindAllStringSubmatch(line, -1)
		if len(match) > 0 {
			s := match[0]
			severity = s[1]
		} else {
			continue
		}

		a0 := strings.Index(line, "<dd>")
		a1 := strings.Index(line, "<ul>")
		if a0 > 0 && a1 > a0 {
			description = line[a0+4 : a1]
		} else {
			log.Error("No description:", line)
			continue
		}

		modVul.Description = strings.Trim(description, "\n")
		modVul.VulName = vulName
		modVul.AppName = "openssl"
		modVul.ModuleName = "openssl"
		modVul.Link = link
		modVul.Score = 0
		if severity == "Critical" {
			modVul.Severity = common.Critical
		} else if severity == "High" {
			modVul.Severity = common.High
		} else if severity == "Moderate" {
			modVul.Severity = common.Medium
		} else if severity == "Low" {
			modVul.Severity = common.Low
		} else {
			continue
		}
		modVul.CVEs = []string{modVul.VulName}
		modVul.FixedVer = fver
		modVul.AffectedVer = aver

		addAppVulMap(&modVul)
		cveCount++
	}
	if cveCount == 0 {
		log.Error("Openssl update CVE FAIL")
		return fmt.Errorf("Openssl update CVE FAIL")
	} else {
		log.WithFields(log.Fields{"cve": cveCount}).Info("Openssl update")
		return nil
	}
}

func getOpensslVulVersion(cve, line string) ([]common.AppModuleVersion, []common.AppModuleVersion, error) {
	match := verRegexp.FindAllStringSubmatch(line, -1)
	if len(match) > 0 {
		fver := make([]common.AppModuleVersion, 0)
		aver := make([]common.AppModuleVersion, 0)
		count := 0

		for i, m := range match {
			if len(m) >= 2 {
				fv := strings.TrimSpace(m[1])
				fver = append(fver, common.AppModuleVersion{Version: fv})

				var av string
				if strings.HasPrefix(m[2], "since ") {
					av = strings.TrimSpace(strings.TrimSpace(m[2][6:]))
				} else {
					av = strings.TrimSpace(strings.TrimSpace(m[2]))
				}

				if i == 0 {
					aver = append(aver, common.AppModuleVersion{OpCode: "lt", Version: fv})
				} else {
					aver = append(aver, common.AppModuleVersion{OpCode: "orlt", Version: fv})
				}
				aver = append(aver, common.AppModuleVersion{OpCode: "gteq", Version: av})
				count += 1
			} else {
				log.WithFields(log.Fields{"match": m}).Error("Unexpected version")
			}
		}

		if count > 0 {
			return fver, aver, nil
		}
	}

	return nil, nil, errors.New("No version info is found")
}
