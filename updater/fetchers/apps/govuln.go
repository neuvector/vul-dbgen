package apps

import (
	"archive/zip"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	log "github.com/sirupsen/logrus"
	"github.com/vul-dbgen/common"
	utils "github.com/vul-dbgen/share"
	"github.com/vul-dbgen/updater/fetchers/ubuntu"
	"google.golang.org/protobuf/encoding/protojson"
)

const goVulnDBPath = "apps/golang-osv.zip"

func loadZipFile(zipFile *zip.File) (*osvschema.Vulnerability, error) {
	file, err := zipFile.Open()
	if err != nil {
		log.Warnf("Could not read %s: %v", zipFile.Name, err)
		return nil, err
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		log.Warnf("Could not read %s: %v", zipFile.Name, err)
		return nil, err
	}

	var vulnerability osvschema.Vulnerability

	if err := protojson.Unmarshal(content, &vulnerability); err != nil {
		log.Warnf("%s is not a valid JSON file: %v", zipFile.Name, err)
		return nil, err
	}
	return &vulnerability, nil
}

func getUrl(vulnerability *osvschema.Vulnerability) string {
	link := ""

	if vulnerability.DatabaseSpecific != nil {
		fields := vulnerability.DatabaseSpecific.GetFields()

		if urlField, ok := fields["url"]; ok {
			link = urlField.GetStringValue()
		}
	}

	if link == "" {
		for _, ref := range vulnerability.References {
			link = ref.Url
			break
		}
	}

	return link
}

// getSeverityLevel follow the neuvector severity mapping
func getSeverityLevel(score float64) common.Priority {
	if score >= 7.0 {
		return common.High
	} else if score >= 4.0 {
		return common.Medium
	}
	return common.Low
}

// convertGoOSVToAppModuleVul converts a Go OSV vulnerability to an AppModuleVul
// Note: Go OSV typically lacks severity ratings. Calibration from Ubuntu mapping will be applied later if available.
func convertGoOSVToAppModuleVul(vulnerability *osvschema.Vulnerability) ([]*common.AppModuleVul, utils.Set) {
	appVuls := make([]*common.AppModuleVul, 0)
	cvesIncludeGoVuln := utils.NewSet()
	for _, affected := range vulnerability.Affected {
		appVul := &common.AppModuleVul{
			VulName:     vulnerability.Id,
			AppName:     "go",
			ModuleName:  "go:" + affected.Package.Name,
			Description: vulnerability.Details,
			IssuedDate:  vulnerability.Published.AsTime(),
			LastModDate: vulnerability.Modified.AsTime(),
			CVEs:        make([]string, 0),
			FixedVer:    make([]common.AppModuleVersion, 0),
			AffectedVer: make([]common.AppModuleVersion, 0),
			Link:        getUrl(vulnerability),
		}

		// go OSV does not support the severity, only support the score. https://go.dev/doc/security/vuln/
		if len(vulnerability.Severity) > 0 {
			// get the first severity
			for _, severity := range vulnerability.Severity {
				if severity.Type == osvschema.Severity_CVSS_V2 {
					score, err := strconv.ParseFloat(severity.Score, 64)
					if err != nil {
						log.Warnf("Could not parse score: %v in vulnerability: %s", err, vulnerability.Id)
						continue
					}
					appVul.Score = score
				} else if severity.Type == osvschema.Severity_CVSS_V3 {
					score, err := strconv.ParseFloat(severity.Score, 64)
					if err != nil {
						log.Warnf("Could not parse score: %v in vulnerability: %s", err, vulnerability.Id)
						continue
					}
					appVul.ScoreV3 = score
					appVul.Severity = getSeverityLevel(score)
				}
			}
		}

		if appVul.Description == "" {
			appVul.Description = vulnerability.Summary
		}

		// Extract CVEs from aliases
		for _, alias := range vulnerability.Aliases {
			if strings.HasPrefix(alias, "CVE-") {
				appVul.CVEs = append(appVul.CVEs, alias)
				cvesIncludeGoVuln.Add(alias)
			}
		}

		// Parse version ranges (SEMVER)
		for _, r := range affected.Ranges {
			if r.Type != osvschema.Range_SEMVER {
				continue
			}

			for _, event := range r.Events {
				if event.Introduced != "" {
					appVul.AffectedVer = append(appVul.AffectedVer, common.AppModuleVersion{
						OpCode:  "gteq",
						Version: event.Introduced,
					})
				}

				if event.Fixed != "" {
					appVul.AffectedVer = append(appVul.AffectedVer, common.AppModuleVersion{
						OpCode:  "lt",
						Version: event.Fixed,
					})
				}
			}
		}
		appVuls = append(appVuls, appVul)
	}
	return appVuls, cvesIncludeGoVuln
}

func prepareUbuntuSeverityMap(cvesIncludeGoVuln utils.Set) (map[string]common.Vulnerability, error) {
	log.Info("Preparing Ubuntu severity map...")
	ubuntuFetcher := ubuntu.UbuntuFetcher{
		CvesIncludeGoVuln: cvesIncludeGoVuln,
	}
	response, err := ubuntuFetcher.FetchUpdate()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to fetch Ubuntu vulnerabilities")
		return nil, err
	}

	ubuntuVulnMap := make(map[string]common.Vulnerability)
	for _, vuln := range response.Vulnerabilities {
		ubuntuVulnMap[vuln.Name] = vuln
	}
	log.WithFields(log.Fields{"count": len(ubuntuVulnMap)}).Info("Ubuntu severity map prepared")
	return ubuntuVulnMap, nil
}

func getPreferredCVEKey(appVul *common.AppModuleVul) string {
	for _, alias := range appVul.CVEs {
		return alias
	}
	return appVul.VulName
}

func loadGoOSVVulnerabilities() (map[string]*common.AppModuleVul, utils.Set, error) {
	log.Info("Loading Go OSV vulnerabilities...")
	goVulnMap := make(map[string]*common.AppModuleVul)
	cvesIncludeGoVuln := utils.NewSet()

	dataFile := fmt.Sprintf("%s%s", common.CVESourceRoot, goVulnDBPath)
	zipReader, err := zip.OpenReader(dataFile)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to open Go OSV zip file")
		return nil, nil, err
	}
	defer zipReader.Close()

	for _, file := range zipReader.File {
		vulnerability, err := loadZipFile(file)
		if err != nil {
			log.WithFields(log.Fields{"file": file.Name, "error": err}).Warn("Failed to load Go OSV file")
			continue
		}

		appVuls, cvesIncludeGoVulnNew := convertGoOSVToAppModuleVul(vulnerability)
		for _, appVul := range appVuls {
			goVulnMap[getPreferredCVEKey(appVul)] = appVul
		}
		cvesIncludeGoVuln = cvesIncludeGoVuln.Union(cvesIncludeGoVulnNew)
	}

	log.WithFields(log.Fields{"count": len(goVulnMap)}).Info("Go OSV vulnerabilities loaded")
	return goVulnMap, cvesIncludeGoVuln, nil
}

func calibrateAndMerge(goVulnMap map[string]*common.AppModuleVul, ubuntuVulnerabilityMap map[string]common.Vulnerability) {
	if ubuntuVulnerabilityMap == nil {
		return
	}

	whileListGoVuls := utils.NewSetFromSlice([]interface{}{
		"GO-2022-0635",
		"GO-2022-0646",
		"GO-2025-3918",
		"GO-2025-3917",
		"GO-2025-3919",
	})

	for cve, appVul := range goVulnMap {
		if ubuntuVulnerability, ok := ubuntuVulnerabilityMap[cve]; ok {
			appVul.VulName = ubuntuVulnerability.Name
			appVul.Severity = ubuntuVulnerability.Severity
			appVul.Score = ubuntuVulnerability.CVSSv2.Score
			appVul.Vectors = ubuntuVulnerability.CVSSv2.Vectors
			appVul.ScoreV3 = ubuntuVulnerability.CVSSv3.Score
			appVul.VectorsV3 = ubuntuVulnerability.CVSSv3.Vectors
			appVul.Link = ubuntuVulnerability.Link
		}

		if whileListGoVuls.Contains(appVul.VulName) {
			continue
		}
		addAppVulMap(appVul)
	}
}

// govulnUpdate performs the Go vulnerability update process.
func govulnUpdate() error {
	log.Info("Starting Go vulnerability update...")

	// Load Go OSV vulnerabilities and initialize the application vulnerability map.
	goVulnMap, cvesIncludeGoVuln, err := loadGoOSVVulnerabilities()
	if err != nil {
		return fmt.Errorf("failed to load Go OSV vulnerabilities: %w", err)
	}

	// Prepare the Ubuntu severity map using the CVEs from Go vulnerabilities, since govuln does not support the severity.
	ubuntuVulnMap, err := prepareUbuntuSeverityMap(cvesIncludeGoVuln)
	if err != nil {
		return fmt.Errorf("failed to prepare Ubuntu severity map: %w", err)
	}

	// Merge the loaded vulnerabilities with the Ubuntu severity map.
	calibrateAndMerge(goVulnMap, ubuntuVulnMap)
	log.Info("Go vulnerability update completed successfully")
	return nil
}
