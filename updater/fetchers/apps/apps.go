package apps

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/vul-dbgen/common"
	utils "github.com/vul-dbgen/share"
	"github.com/vul-dbgen/updater"
)

// Must not use pointer, some modules use the same object
var vulMap map[string]*common.AppModuleVul = make(map[string]*common.AppModuleVul)
var vulCache utils.Set = utils.NewSet()
var cveCalibrate map[string][]common.AppModuleVersion = make(map[string][]common.AppModuleVersion)

// Sometimes source doesn't remove withdrawn CVEs
var withdrawnCVEs = map[string]struct{}{"CVE-2021-23334": {}}

// This is a workaround to use import to control app db generation
type AppFetcher struct{}

func init() {
	updater.RegisterAppFetcher("app", &AppFetcher{})
}

func addAppVulMap(mv *common.AppModuleVul) {
	key := fmt.Sprintf("%s:%s", mv.ModuleName, mv.VulName)
	vulMap[key] = mv
}

func (f *AppFetcher) FetchUpdate() (resp updater.AppFetcherResponse, err error) {
	cveCalibrationLoad()

	// temporarily disable reading cvedetails site until the feed is available
	// if err = cvedetailUpdate(); err != nil {
	// 	return resp, err
	// }
	if err = ghsaUpdate(); err != nil {
		return resp, err
	}
	if err = nginxUpdate(); err != nil {
		return resp, err
	}
	if err = opensslUpdate(); err != nil {
		return resp, err
	}
	if err = rubyUpdate(); err != nil {
		return resp, err
	}
	if err = k8sUpdate(); err != nil {
		return resp, err
	}
	if err = openshiftUpdate(); err != nil {
		return resp, err
	}
	if err = manualUpdate(); err != nil {
		return resp, err
	}
	for key, mv := range vulMap {
		//Manually remove some withdrawn CVE entries.
		if _, ok := withdrawnCVEs[mv.VulName]; ok {
			delete(vulMap, key)
			continue
		}
		// Keep all CWE and GHSA vulnerabilities for now.
		if !strings.HasPrefix(mv.VulName, "CWE-") && !strings.HasPrefix(mv.VulName, "GHSA-") {
			if s := strings.Index(mv.VulName, "-"); s != -1 {
				if year, err := common.ParseYear(mv.VulName[s+1:]); err != nil {
					log.WithFields(log.Fields{"cve": mv.VulName}).Error("Unable to parse year from CVE name")
					continue
				} else if year < common.FirstYear {
					continue
				}
			}
		}

		common.DEBUG_VULN(mv, "app")

		resp.Vulnerabilities = append(resp.Vulnerabilities, mv)
	}

	return resp, err
}

func cveCalibrationLoad() {
	dat, err := ioutil.ReadFile("apps_calibration")
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Info("open apps_calibration fail")
		return
	}
	scanner := bufio.NewScanner(strings.NewReader(string(dat)))
	for scanner.Scan() {
		line := scanner.Text()
		i := strings.Index(line, ":")
		if i > 0 {
			var m common.AppModuleVersion
			if err := json.Unmarshal([]byte(line[i+1:]), &m); err == nil {
				if mm, ok := cveCalibrate[line[:i]]; ok {
					cveCalibrate[line[:i]] = append(mm, m)
				} else {
					cveCalibrate[line[:i]] = []common.AppModuleVersion{m}
				}
			}
		}
	}
}

func (f *AppFetcher) Clean() {
}
