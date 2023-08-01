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
var vulMap map[string]common.AppModuleVul = make(map[string]common.AppModuleVul)
var vulCache utils.Set = utils.NewSet()
var cveCalibrate map[string][]common.AppModuleVersion = make(map[string][]common.AppModuleVersion)

// This is a workaround to use import to control app db generation
type AppFetcher struct{}

func init() {
	updater.RegisterAppFetcher("app", &AppFetcher{})
}

func addAppVulMap(mv *common.AppModuleVul) {
	key := fmt.Sprintf("%s:%s", mv.ModuleName, mv.VulName)
	vulMap[key] = *mv
}

func pickCriticalCVE(nvd updater.MetadataFetcher, cves []string) (string, float64, string, float64, bool) {
	var mvv2, mvv3 string
	var msv2, msv3 float64
	var found bool

	for _, cve := range cves {
		vv2, sv2, vv3, sv3, ok := nvd.LookupMetadata(cve)
		if !ok {
			continue
		}

		found = true
		if sv3 > msv3 {
			mvv2 = vv2
			mvv3 = vv3
			msv2 = sv2
			msv3 = sv3
			continue
		} else if sv3 < msv3 {
			continue
		}
		if sv2 > msv2 {
			mvv2 = vv2
			mvv3 = vv3
			msv2 = sv2
			msv3 = sv3
		}
	}
	return mvv2, msv2, mvv3, msv3, found
}

func parseAffectedVersion(str string) common.AppModuleVersion {
	var vo string

	if strings.Contains(str, "||") {
		vo += "or"
		str = strings.TrimLeft(str, "||")
	}
	if strings.Contains(str, "<") {
		vo += "lt"
		str = strings.TrimLeft(str, "<")
	} else if strings.Contains(str, ">") {
		vo += "gt"
		str = strings.TrimLeft(str, ">")
	}
	if strings.Contains(str, "=") {
		vo += "eq"
		str = strings.TrimLeft(str, "=")
	}

	mv := common.AppModuleVersion{OpCode: vo, Version: str}
	return mv
}

func (f *AppFetcher) FetchUpdate(metadataFetchers map[string]updater.MetadataFetcher) (resp updater.AppFetcherResponse, err error) {
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

	nvd, _ := metadataFetchers["NVD"]

	for _, mv := range vulMap {
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

		// Use NVD to correct affected version.
		if len(mv.AffectedVer) == 0 || len(mv.FixedVer) == 0 {
			if affects, fixes, ok := nvd.AddAffectedVersion(mv.VulName); ok {
				// log.WithFields(log.Fields{"name": mv.VulName, "affects": affects, "fixes": fixes}).Info("jar update")
				if len(mv.AffectedVer) == 0 {
					mv.AffectedVer = make([]common.AppModuleVersion, 0)
					for _, v := range affects {
						ver := parseAffectedVersion(v)
						mv.AffectedVer = append(mv.AffectedVer, ver)
					}
				}

				if len(mv.FixedVer) == 0 {
					mv.FixedVer = make([]common.AppModuleVersion, 0)
					for _, v := range fixes {
						ver := parseAffectedVersion(v)
						mv.FixedVer = append(mv.FixedVer, ver)
					}
				}
			}
		}

		if len(mv.CVEs) > 0 {
			vv2, sv2, vv3, sv3, ok := pickCriticalCVE(nvd, mv.CVEs)

			// Fix score
			if mv.Score == 0 && ok {
				mv.Score = sv2
			}
			if mv.Score == 0 && mv.Severity == "High" {
				mv.Score = 8
			}
			if mv.Score == 0 {
				mv.Score = 5
			}

			if mv.ScoreV3 == 0 && ok {
				mv.ScoreV3 = sv3
			}
			if mv.ScoreV3 == 0 && mv.Severity == "High" {
				mv.ScoreV3 = 8
			}
			if mv.ScoreV3 == 0 {
				mv.ScoreV3 = 5
			}

			if ok {
				mv.Vectors = vv2
				mv.VectorsV3 = vv3
			}

			// if mv.Severity == "" {
			// similar logic in nvd AddMetadata()
			if mv.ScoreV3 >= 7 || mv.Score >= 7 {
				mv.Severity = "High"
			} else if mv.ScoreV3 >= 4 || mv.Score >= 4 {
				mv.Severity = "Medium"
			}

			// Add update date
			if issue, last, ok := nvd.AddCveDate(mv.CVEs[0]); ok {
				if mv.IssuedDate.IsZero() {
					mv.IssuedDate = issue
				}
				if mv.LastModDate.IsZero() {
					mv.LastModDate = last
				}
			}
		}

		if mv.Severity == "" {
			continue
		}

		// if mv.ModuleName == "kubernetes" {
		// 	log.WithFields(log.Fields{"cve": mv}).Error()
		// }

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
