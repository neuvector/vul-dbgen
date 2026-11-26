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
	nginxuri = "http://nginx.org/en/security_advisories.html"
)

// FetchUpdate gets vulnerability updates from the Nginx OVAL definitions.
func nginxUpdate() error {
	log.Info("fetching Nginx vulnerabilities")

	r, err := http.Get(nginxuri)
	if err != nil {
		log.Debugf("could not download Nginx's update list: %s", err.Error())
		return err
	}
	defer r.Body.Close()

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	return parseNginxVulnerabilities(string(body))
}

func parseNginxVulnerabilities(body string) error {
	cveNameRegexp := regexp.MustCompile(`">([A-Z0-9\-]+)</a><br>`)
	affectedVerRegexp := regexp.MustCompile(`<br>Vulnerable: ([0-9a-zA-Z\s\/\.\-,]*)`)
	fixedVerRegexp := regexp.MustCompile(`<br>Not vulnerable: ([0-9a-zA-Z\.\+\-,\s]*)<br>`)
	descriptionRegexp := regexp.MustCompile(`<li><p>(.*?)<br>`)
	severityRegexp := regexp.MustCompile(`<br>Severity: <?b?>?(high|major|medium|low)<?/?b?>?<br>`)
	linkRegexp := regexp.MustCompile(`<a href="([^"]*)">Advisory`)

	var cveCount int
	for _, cve := range strings.Split(body, "</p></li>") {
		match := descriptionRegexp.FindAllStringSubmatch(cve, -1)
		if len(match) == 0 {
			log.WithFields(log.Fields{"cve": cve}).Info("Not match Description")
			continue
		}
		description := match[0][1]

		match = cveNameRegexp.FindAllStringSubmatch(cve, -1)
		if len(match) == 0 {
			log.WithFields(log.Fields{"cve": cve}).Info("Not match name")
			continue
		}
		name := match[0][1]

		match = affectedVerRegexp.FindAllStringSubmatch(cve, -1)
		if len(match) == 0 {
			log.WithFields(log.Fields{"cve": cve}).Info("Not match affectedVer")
			continue
		}
		affectedVer := match[0][1]
		if affectedVer == "" {
			log.WithFields(log.Fields{"cve": cve}).Info("no affected version found")
			continue
		}

		fixedVer := ""
		if match = fixedVerRegexp.FindAllStringSubmatch(cve, -1); len(match) > 0 {
			fixedVer = match[0][1]
		}

		modVul := common.AppModuleVul{
			VulName:     name,
			AppName:     "nginx",
			ModuleName:  "nginx",
			Description: description,
			Severity:    common.Unknown,
			AffectedVer: getAffectedVersion(affectedVer),
			FixedVer:    getFixedVersion(fixedVer),
			CVEs:        []string{name},
		}
		if match = severityRegexp.FindAllStringSubmatch(cve, -1); len(match) > 0 {
			severity := strings.Replace(match[0][1], "major", string(common.High), -1)
			severity = strings.Replace(severity, "medium", string(common.Medium), -1)
			severity = strings.Replace(severity, "low", string(common.Low), -1)
			modVul.Severity = common.Priority(severity)
		}
		if match = linkRegexp.FindAllStringSubmatch(cve, -1); len(match) > 0 {
			modVul.Link = match[0][1]
		}

		addAppVulMap(&modVul)
		cveCount++
	}
	if cveCount == 0 {
		log.Error("Nginx update CVE FAIL")
		return fmt.Errorf("Nginx update CVE FAIL")
	}
	log.WithFields(log.Fields{"cve": cveCount}).Info("Nginx update")
	return nil
}

// 0.6.18-1.9.9
// 1.1.4-1.2.8, 1.3.9-1.4.0
var versionAffectedRegexp1 = regexp.MustCompile(`([0-9\.]+)\-([0-9\.]+)`)
var versionAffectedRegexp2 = regexp.MustCompile(`([0-9\.]+)`)

func getAffectedVersion(str string) []common.AppModuleVersion {
	modVerArr := make([]common.AppModuleVersion, 0)
	var mv common.AppModuleVersion
	if strings.Contains(str, "all") {
		mv = common.AppModuleVersion{OpCode: "", Version: "All"}
		modVerArr = append(modVerArr, mv)
		return modVerArr
	}
	match := versionAffectedRegexp1.FindAllStringSubmatch(str, -1)
	for i, s := range match {
		if len(s) == 3 {
			if i > 0 {
				mv = common.AppModuleVersion{OpCode: "orgteq", Version: s[1]}
			} else {
				mv = common.AppModuleVersion{OpCode: "gteq", Version: s[1]}
			}
			modVerArr = append(modVerArr, mv)
			mv = common.AppModuleVersion{OpCode: "lteq", Version: s[2]}
			modVerArr = append(modVerArr, mv)
		}
	}
	if len(modVerArr) == 0 {
		match := versionAffectedRegexp2.FindAllStringSubmatch(str, -1)
		for _, s := range match {
			if len(s) == 2 {
				mv = common.AppModuleVersion{OpCode: "", Version: s[1]}
				modVerArr = append(modVerArr, mv)
			}
		}
	}
	return modVerArr

}

var versionFixedRegexp = regexp.MustCompile(`([0-9\.\+]+)`)

func getFixedVersion(str string) []common.AppModuleVersion {
	modVerArr := make([]common.AppModuleVersion, 0)
	if strings.Contains(str, "none") {
		mv := common.AppModuleVersion{OpCode: "", Version: "None"}
		modVerArr = append(modVerArr, mv)
		return modVerArr
	}
	match := versionFixedRegexp.FindAllStringSubmatch(str, -1)
	for _, s := range match {
		if len(s) == 2 {
			v := strings.Replace(s[1], "+", "", -1)
			mv := common.AppModuleVersion{OpCode: "gteq", Version: v}
			modVerArr = append(modVerArr, mv)
		}
	}
	return modVerArr

}
