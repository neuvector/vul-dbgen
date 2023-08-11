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
	var cveNameRegexp = regexp.MustCompile(`">([A-Z0-9\-]*)</a><br>`)
	var affectedVerRegexp = regexp.MustCompile(`<br>Vulnerable: ([0-9a-zA-Z\s\/\.\-,]*)`)
	var fixedVerRegexp = regexp.MustCompile(`<br>Not vulnerable: ([0-9a-zA-Z\.+\-,\s]*)<br>`)
	var descriptionRegexp = regexp.MustCompile(`<li><p>(.*)<br>Severity:`)
	var severityRegexp = regexp.MustCompile(`<br>Severity: <?b?>?(high|major|medium|low)<?/?b?>?<br>`)
	var linkRegexp = regexp.MustCompile(`<a href="(.*)">Advisory`)

	var cveCount int
	log.Info("fetching Nginx vulnerabilities")

	// Fetch the update list.
	r, err := http.Get(nginxuri)
	if err != nil {
		log.Debugf("could not download Nginx's update list: %s", err.Error())
		return err
	}
	// Get the list of nginx that we have to process.
	defer r.Body.Close()
	body, _ := ioutil.ReadAll(r.Body)

	cves := strings.Split(string(body), "</p></li>")
	var name, affectedVer, fixedVer string
	var modVul common.AppModuleVul

	for _, cve := range cves {
		match := descriptionRegexp.FindAllStringSubmatch(cve, -1)
		if len(match) > 0 {
			s := match[0]
			modVul.Description = s[1]
		} else {
			log.WithFields(log.Fields{"cve": cve}).Info("Not match Description")
			continue
		}
		match = cveNameRegexp.FindAllStringSubmatch(cve, -1)
		if len(match) > 0 {
			s := match[0]
			name = s[1]
		} else {
			log.WithFields(log.Fields{"cve": cve}).Info("Not match name")
			continue
		}
		match = affectedVerRegexp.FindAllStringSubmatch(cve, -1)
		if len(match) > 0 {
			s := match[0]
			affectedVer = s[1]
		} else {
			log.WithFields(log.Fields{"cve": cve}).Info("Not match affectedVer")
			continue
		}
		match = fixedVerRegexp.FindAllStringSubmatch(cve, -1)
		if len(match) > 0 {
			s := match[0]
			fixedVer = s[1]
		}
		match = severityRegexp.FindAllStringSubmatch(cve, -1)
		if len(match) > 0 {
			s := match[0]
			modVul.Severity = strings.Replace(s[1], "major", "High", -1)
			modVul.Severity = strings.Replace(modVul.Severity, "medium", "Medium", -1)
			modVul.Severity = strings.Replace(modVul.Severity, "low", "Low", -1)
		} else {
			continue
		}
		match = linkRegexp.FindAllStringSubmatch(cve, -1)
		if len(match) > 0 {
			s := match[0]
			modVul.Link = s[1]
		}
		if affectedVer == "" {
			log.WithFields(log.Fields{"cve": cve}).Info("no affected version found")
			continue
		}
		modVul.AffectedVer = getAffectedVersion(affectedVer)
		modVul.FixedVer = getFixedVersion(fixedVer)

		modVul.VulName = name
		modVul.AppName = "nginx"
		modVul.ModuleName = "nginx"
		modVul.CVEs = []string{name}

		addAppVulMap(&modVul)
		cveCount++
	}
	if cveCount == 0 {
		log.Error("Nginx update CVE FAIL")
		return fmt.Errorf("Nginx update CVE FAIL")
	} else {
		log.WithFields(log.Fields{"cve": cveCount}).Info("Nginx update")
		return nil
	}
}

//0.6.18-1.9.9
//1.1.4-1.2.8, 1.3.9-1.4.0
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
