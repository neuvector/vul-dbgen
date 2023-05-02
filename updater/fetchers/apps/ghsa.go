package apps

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/vul-dbgen/common"
	"github.com/vul-dbgen/updater"
)

const (
	npmDataFile    = "github/npm.data.gz"
	mavenDataFile  = "github/maven.data.gz"
	pipDataFile    = "github/pip.data.gz"
	nugetDataFile  = "github/nuget.data.gz"
	golangDataFile = "github/go.data.gz"
)

type ghsaData struct {
	ID      string `json:"id"`
	Package struct {
		EcoSystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Advisory struct {
		GHSAID      string    `json:"ghsaId"`
		Severity    string    `json:"severity"`
		Summary     string    `json:"summary"`
		Description string    `json:"description"`
		PublishedAt time.Time `json:"publishedAt"`
		UpdatedAt   time.Time `json:"updatedAt"`
		Link        string    `json:"permalink"`
		CVSS        struct {
			Vectors string  `json:"vectorString"`
			Score   float64 `json:"score"`
		} `json:"cvss"`
		Identifiers []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"identifiers"`
		CWEs struct {
			Nodes []struct {
				CWEID string `json:"cweid"`
			} `json:"nodes"`
		} `json:"cwes"`
		References []struct {
			URL string `json:"url"`
		} `json:"references"`
	} `json:"advisory"`
	AffectedVersion string `json:"vulnerableVersionRange"`
	PatchedVersion  struct {
		Identifier string `json:"identifier"`
	} `json:"firstPatchedVersion"`
}

func ghsaUpdate() error {
	log.Info("fetching ghsa vulnerabilities")
	loadGHSAData(npmDataFile, "npm", "")
	loadGHSAData(mavenDataFile, "maven", "")
	loadGHSAData(pipDataFile, "pip", "python:")
	loadGHSAData(nugetDataFile, ".NET", ".NET:")
	loadGHSAData(golangDataFile, "golang", "go:")
	return nil
}

func loadGHSAData(ghsaFile, app, prefix string) error {
	dataFile := fmt.Sprintf("%s%s", updater.CVESourceRoot, ghsaFile)
	f, err := os.Open(dataFile)
	if err != nil {
		log.WithFields(log.Fields{"file": dataFile}).Error("Cannot find local database")
		return fmt.Errorf("Unabled to fetch any vulernabilities")
	}

	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		log.WithFields(log.Fields{"file": dataFile}).Error("Failed to create feed reader")
		return fmt.Errorf("Unabled to fetch any vulernabilities")
	}
	defer gzr.Close()

	var count int
	scanner := bufio.NewScanner(gzr)
	for scanner.Scan() {
		var r ghsaData
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to unmarshal the record")
			continue
		}

		modVul := common.AppModuleVul{
			Description: fmt.Sprintf("%s\n%s\n", r.Advisory.Summary, r.Advisory.Description),
			AffectedVer: getVersion(r.AffectedVersion),
			FixedVer:    getVersion(r.PatchedVersion.Identifier),
			AppName:     app,
			ModuleName:  fmt.Sprintf("%s%s", prefix, r.Package.Name),
			Link:        r.Advisory.Link,
			CVEs:        make([]string, 0),
			IssuedDate:  r.Advisory.PublishedAt,
			LastModDate: r.Advisory.UpdatedAt,
		}

		severity := strings.ToLower(r.Advisory.Severity)
		if severity == "high" || severity == "critical" {
			modVul.Severity = "High"
		} else if severity == "moderate" {
			modVul.Severity = "Medium"
		} else {
			// log.WithFields(log.Fields{"severity": r.Advisory.Severity}).Error("Unknown severity")
			continue
		}

		if r.Advisory.CVSS.Vectors != "" {
			if strings.HasPrefix(r.Advisory.CVSS.Vectors, "CVSS:3") {
				modVul.VectorsV3 = r.Advisory.CVSS.Vectors
				modVul.ScoreV3 = r.Advisory.CVSS.Score
			} else {
				modVul.Vectors = r.Advisory.CVSS.Vectors
				modVul.Score = r.Advisory.CVSS.Score
			}
		}

		if len(modVul.FixedVer) == 1 && modVul.FixedVer[0].Version == "0.0.0" {
			modVul.FixedVer = []common.AppModuleVersion{}
		}

		for _, e := range r.Advisory.Identifiers {
			if e.Type == "CVE" {
				modVul.CVEs = append(modVul.CVEs, e.Value)
			}
		}
		if len(modVul.CVEs) > 0 {
			modVul.VulName = modVul.CVEs[0]
		} else if r.Advisory.GHSAID == "" {
			modVul.VulName = r.Advisory.CWEs.Nodes[0].CWEID
		} else {
			modVul.VulName = r.Advisory.GHSAID
		}

		/*
			if modVul.VulName == "CWE-400" {
				log.WithFields(log.Fields{"id": cve.ID, "module": cve.ModuleName, "fix": modVul.FixedVer, "affect": modVul.AffectedVer}).Debug()
				log.WithFields(log.Fields{"create": modVul.IssuedDate, "update": modVul.LastModDate}).Debug()
			}
		*/

		addAppVulMap(&modVul)
		count++
	}

	if count == 0 {
		log.WithFields(log.Fields{"cve": count}).Error()
		return fmt.Errorf("Unabled to fetch any vulernabilities")
	}

	log.WithFields(log.Fields{"source": ghsaFile, "cve": count}).Info()
	return nil
}

// >=1.3.0 <1.3.2 || >=1.4.0 <1.4.11 || >=1.5.0 <1.5.2
var versionRegexp = regexp.MustCompile(`([\>\<\=\|\s]*)([0-9A-Za-z\.\-]+)`)

func getVersion(str string) []common.AppModuleVersion {
	modVerArr := make([]common.AppModuleVersion, 0)
	match := versionRegexp.FindAllStringSubmatch(str, -1)
	for _, s := range match {
		var vo, vv string
		if len(s) == 3 {
			if strings.Contains(s[0], "||") {
				vo = "or"
			}
			if strings.Contains(s[1], "<") {
				vo += "lt"
			} else if strings.Contains(s[1], ">") {
				vo += "gt"
			}
			if strings.Contains(s[1], "=") {
				vo += "eq"
			}
			vv = s[2]

			if strings.HasPrefix(vv, "v") {
				vv = strings.Replace(vv, "v", "", 1)
			}
			if vo != "" || vv != "" {
				mv := common.AppModuleVersion{OpCode: vo, Version: vv}
				modVerArr = append(modVerArr, mv)
			}
		}
	}
	return modVerArr

}
