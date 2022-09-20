package apps

import (
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

// FetchUpdate gets vulnerability updates from the openssl.
func opensslUpdate() error {
	var cveNameRegexp = regexp.MustCompile(`<a href="(.*)" name="CVE-([0-9\-]+)">`)
	var fixedVerRegexp = regexp.MustCompile(`Fixed in OpenSSL\s*\n*([0-9a-z\.\s]+)`)
	var affectedVerRegexp = regexp.MustCompile(`\(Affected\s+([0-9a-z\.\-,\s]+)\s*\)`)
	var severityRegexp = regexp.MustCompile(`\[([a-zA-Z]+) severity\]`)

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
		match = fixedVerRegexp.FindAllStringSubmatch(line, -1)
		if len(match) > 0 {
			modVul.FixedVer = make([]common.AppModuleVersion, 0)
			for _, m := range match {
				fv := getOpensslFixedVersion(m[1])
				modVul.FixedVer = append(modVul.FixedVer, fv...)
			}
		} else {
			log.Error("No fixed version:", line)
		}
		match = affectedVerRegexp.FindAllStringSubmatch(line, -1)
		if len(match) > 0 {
			modVul.AffectedVer = make([]common.AppModuleVersion, 0)
			for i, m := range match {
				av := getOpensslAffectedVersion(i, m[1])
				modVul.AffectedVer = append(modVul.AffectedVer, av...)
			}
		} else {
			log.Error("No affected version:", line)
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
		modVul.VulName = "CVE-" + cveNumber
		modVul.ModuleName = "openssl"
		modVul.Link = link
		modVul.Score = 0
		if severity == "Critical" || severity == "High" {
			modVul.Severity = "High"
		} else if severity == "Moderate" {
			modVul.Severity = "Medium"
		} else {
			continue
		}
		modVul.CVEs = []string{modVul.VulName}

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
func getOpensslFixedVersion(str string) []common.AppModuleVersion {
	modVerArr := make([]common.AppModuleVersion, 0)
	mv := common.AppModuleVersion{OpCode: "", Version: strings.TrimSpace(str)}
	modVerArr = append(modVerArr, mv)
	return modVerArr
}
func getOpensslAffectedVersion(i int, str string) []common.AppModuleVersion {
	modVerArr := make([]common.AppModuleVersion, 0)

	vers := strings.Split(string(str), ",")
	for j, v := range vers {
		if strings.Contains(v, "-") {
			subvs := strings.Split(v, "-")
			if len(subvs) == 2 {
				if i > 0 || j > 0 {
					mv1 := common.AppModuleVersion{OpCode: "orgteq", Version: strings.TrimSpace(subvs[0])}
					modVerArr = append(modVerArr, mv1)
				} else {
					mv1 := common.AppModuleVersion{OpCode: "gteq", Version: strings.TrimSpace(subvs[0])}
					modVerArr = append(modVerArr, mv1)
				}
				mv2 := common.AppModuleVersion{OpCode: "lteq", Version: strings.TrimSpace(subvs[1])}
				modVerArr = append(modVerArr, mv2)
			}
		} else {
			mv := common.AppModuleVersion{OpCode: "", Version: strings.TrimSpace(v)}
			modVerArr = append(modVerArr, mv)
		}
	}
	return modVerArr
}
