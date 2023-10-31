package updater

import (
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/vul-dbgen/common"
	"github.com/vul-dbgen/updater/nvd"
)

const (
	flagName      = "updater/last"
	notesFlagName = "updater/notes"

	CVESourceRoot = "vul-source/"
)

type RawFile struct {
	Name string
	Raw  []byte
}

func IgnoreSeverity(s common.Priority) bool {
	return s != common.Critical && s != common.High && s != common.Medium && s != common.Low
}

// Update fetches all the vulnerabilities from the registered fetchers, upserts
// them into the database and then sends notifications.
func Update(datastore Datastore) bool {
	log.Info("updating vulnerabilities")

	// Fetch updates.
	status, osVuls, appVuls, rawFiles := fetch(datastore)
	if !status {
		log.WithFields(log.Fields{"status": status}).Error("Vulnerability update FAIL")
		return false
	}

	// Insert vulnerabilities.
	err := datastore.InsertVulnerabilities(osVuls, appVuls, rawFiles)
	if err != nil {
		log.Errorf("an error occured when inserting vulnerabilities for update: %s", err)
		return false
	}
	osVuls = nil
	appVuls = nil
	rawFiles = nil

	log.Info("update finished")
	return true
}

const cveURLPrefix = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="

func xslateUbuntuUpstream(vuls []Vulnerability) []common.AppModuleVul {
	upstream := make([]common.AppModuleVul, 0)
	for _, v := range vuls {
		if v.Namespace == "ubuntu:upstream" {
			for _, ff := range v.FixedIn {
				mv := common.AppModuleVul{
					VulName:     v.Name,
					ModuleName:  ff.Name,
					Description: v.Description,
					Link:        cveURLPrefix + v.Name,
					Severity:    v.Severity,
					AffectedVer: []common.AppModuleVersion{common.AppModuleVersion{OpCode: "lt", Version: ff.Version.String()}},
					FixedVer:    []common.AppModuleVersion{common.AppModuleVersion{OpCode: "gteq", Version: ff.Version.String()}},
				}
				upstream = append(upstream, mv)
			}
		}
	}
	return upstream
}

func fetchDistroVul() (bool, []*Vulnerability) {
	log.Info()

	status := true
	var responseC = make(chan *FetcherResponse, 0)

	// Fetch updates in parallel.
	for n, f := range fetchers {
		go func(name string, fetcher Fetcher) {
			response, err := fetcher.FetchUpdate()
			if err != nil {
				log.WithFields(log.Fields{"name": name, "error": err}).Error("Distro CVE update FAIL")
				status = false
				responseC <- nil
				return
			}

			responseC <- &response
		}(n, f)
	}

	// Collect results of updates.
	var vuls []*Vulnerability
	for i := 0; i < len(fetchers); i++ {
		resp := <-responseC
		if resp != nil {
			vuls = append(vuls, doVulnerabilitiesNamespacing(resp.Vulnerabilities)...)
		}
	}

	close(responseC)
	return status, vuls
}

func fetchAppVul() (bool, []*common.AppModuleVul) {
	log.Info()

	var appVuls []*common.AppModuleVul

	for name, f := range appFetchers {
		response, err := f.FetchUpdate()
		if err != nil {
			log.WithFields(log.Fields{"name": name, "error": err}).Error("App CVE update FAIL")
			return false, nil
		} else {
			appVuls = append(appVuls, response.Vulnerabilities...)
		}
	}

	return true, appVuls
}

func correctAppAffectedVersion(appVuls []*common.AppModuleVul) {
	for _, app := range appVuls {
		if len(app.AffectedVer) == 0 || len(app.FixedVer) == 0 {
			if affects, fixes, ok := nvd.NVD.GetAffectedVersion(app.VulName); ok {
				// log.WithFields(log.Fields{"name": app.VulName, "affects": affects, "fixes": fixes}).Info("jar update")
				if len(app.AffectedVer) == 0 {
					app.AffectedVer = make([]common.AppModuleVersion, 0)
					for _, v := range affects {
						ver := parseAffectedVersion(v)
						app.AffectedVer = append(app.AffectedVer, ver)
					}
				}

				if len(app.FixedVer) == 0 {
					app.FixedVer = make([]common.AppModuleVersion, 0)
					for _, v := range fixes {
						ver := parseAffectedVersion(v)
						app.FixedVer = append(app.FixedVer, ver)
					}
				}
			}
		}
	}
}

func fetchRawData() (bool, []*RawFile) {
	log.Info()

	status := true
	var rawFiles []*RawFile
	var responseR = make(chan *RawFetcherResponse, 0)

	for n, f := range rawFetchers {
		go func(name string, fetcher RawFetcher) {
			response, err := fetcher.FetchUpdate()
			if err != nil {
				log.WithFields(log.Fields{"name": name, "error": err}).Error("RAW update FAIL")
				status = false
				responseR <- nil
				return
			}

			responseR <- &response
		}(n, f)
	}

	// Collect results of updates.
	for i := 0; i < len(rawFetchers); i++ {
		resp := <-responseR
		if resp != nil {
			rawFiles = append(rawFiles, &RawFile{Name: resp.Name, Raw: resp.Raw})
		}
	}

	close(responseR)
	return status, rawFiles
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

func enrichAppMeta(meta *common.NVDMetadata, v *common.AppModuleVul) {
	if v.ScoreV3 > meta.CVSSv3.Score {
		meta.CVSSv3.Score = v.ScoreV3
		meta.CVSSv3.Vectors = v.VectorsV3
	}
	if v.Score > meta.CVSSv2.Score {
		meta.CVSSv2.Score = v.Score
		meta.CVSSv2.Vectors = v.Vectors
	}
	if meta.PublishedDate.IsZero() {
		meta.PublishedDate = v.IssuedDate
	}
	if meta.LastModifiedDate.IsZero() {
		meta.LastModifiedDate = v.LastModDate
	}
}

func enrichDistroMeta(meta *common.NVDMetadata, v *Vulnerability, cve *CVE) {
	if cve.CVSSv3.Score > meta.CVSSv3.Score {
		meta.CVSSv3 = cve.CVSSv3
	}
	if cve.CVSSv2.Score > meta.CVSSv2.Score {
		meta.CVSSv2 = cve.CVSSv2
	}
	if meta.PublishedDate.IsZero() {
		meta.PublishedDate = v.IssuedDate
	}
	if meta.LastModifiedDate.IsZero() {
		meta.LastModifiedDate = v.LastModDate
	}
}

func fixSeverityScore(feedSeverity common.Priority, maxCVSSv2, maxCVSSv3 *common.CVSS) common.Priority {
	// For NVSHAS-4709, always set the severity by CVSS scores
	var severity common.Priority
	if maxCVSSv3.Score >= 7 || maxCVSSv2.Score >= 7 {
		severity = common.High
	} else if maxCVSSv3.Score >= 4 || maxCVSSv2.Score >= 4 {
		severity = common.Medium
	} else if maxCVSSv3.Score >= 1 || maxCVSSv2.Score >= 1 {
		severity = common.Low
	} else {
		severity = feedSeverity
	}

	if maxCVSSv3.Score == 0 {
		switch severity {
		case common.High:
			maxCVSSv3.Score = 7
		case common.Medium:
			maxCVSSv3.Score = 4
		case common.Low:
			maxCVSSv3.Score = 1
		}
	}
	if maxCVSSv2.Score == 0 {
		switch severity {
		case common.High:
			maxCVSSv2.Score = 7
		case common.Medium:
			maxCVSSv2.Score = 4
		case common.Low:
			maxCVSSv2.Score = 1
		}
	}
	return severity
}

func assignMetadata(vuls []*Vulnerability, apps []*common.AppModuleVul) ([]*Vulnerability, []*common.AppModuleVul) {
	cveMap := make(map[string]*common.NVDMetadata)

	// Use two loops to cross-reference metadata provided by all feeds and nvd

	// first loop, for each cve merge meta with NVD
	for _, v := range vuls {
		cves := []CVE{CVE{Name: v.Name}}
		if len(v.CVEs) > 0 {
			cves = v.CVEs
		}

		for _, cve := range cves {
			// Lookup meta map first, if entry exists, means the NVD has been searched
			if meta, ok := cveMap[cve.Name]; ok {
				enrichDistroMeta(meta, v, &cve)
			} else {
				// lookup NVD and store the metadata
				meta, ok := nvd.NVD.GetMetadata(cve.Name)
				if ok {
					enrichDistroMeta(meta, v, &cve)
				} else {
					meta = &common.NVDMetadata{
						CVSSv3:           cve.CVSSv3,
						CVSSv2:           cve.CVSSv2,
						PublishedDate:    v.IssuedDate,
						LastModifiedDate: v.LastModDate,
					}
				}

				cveMap[cve.Name] = meta
			}
		}
	}

	for _, app := range apps {
		for _, cve := range app.CVEs {
			// Lookup meta map first, if entry exists, means the NVD has been searched
			if meta, ok := cveMap[cve]; ok {
				enrichAppMeta(meta, app)
			} else {
				// lookup NVD and store the metadata
				meta, ok := nvd.NVD.GetMetadata(cve)
				if ok {
					enrichAppMeta(meta, app)
				} else {
					meta = &common.NVDMetadata{
						CVSSv3:           common.CVSS{Score: app.ScoreV3, Vectors: app.VectorsV3},
						CVSSv2:           common.CVSS{Score: app.Score, Vectors: app.Vectors},
						PublishedDate:    app.IssuedDate,
						LastModifiedDate: app.LastModDate,
					}
				}
				cveMap[cve] = meta
			}
		}
	}

	// second loop, assign the best score to the record
	outVuls := make([]*Vulnerability, 0)
	outApps := make([]*common.AppModuleVul, 0)

	for _, v := range vuls {
		cves := []CVE{CVE{Name: v.Name}}
		if len(v.CVEs) > 0 {
			cves = v.CVEs
		}

		var maxCVSSv3, maxCVSSv2 common.CVSS
		for _, cve := range cves {
			if meta, ok := cveMap[cve.Name]; ok {
				if v.IssuedDate.IsZero() {
					v.IssuedDate = meta.PublishedDate
				}
				if v.LastModDate.IsZero() {
					v.LastModDate = meta.LastModifiedDate
				}
				if maxCVSSv3.Score < meta.CVSSv3.Score {
					maxCVSSv3 = meta.CVSSv3
				}
				if maxCVSSv2.Score < meta.CVSSv2.Score {
					maxCVSSv2 = meta.CVSSv2
				}
			}
		}

		severity := fixSeverityScore(v.Severity, &maxCVSSv2, &maxCVSSv3)

		v.Severity = severity
		v.CVSSv3 = maxCVSSv3
		v.CVSSv2 = maxCVSSv2

		if !IgnoreSeverity(v.Severity) {
			outVuls = append(outVuls, v)
		}
	}

	for _, app := range apps {
		var maxCVSSv3, maxCVSSv2 common.CVSS
		for _, cve := range app.CVEs {
			if meta, ok := cveMap[cve]; ok {
				if app.IssuedDate.IsZero() {
					app.IssuedDate = meta.PublishedDate
				}
				if app.LastModDate.IsZero() {
					app.LastModDate = meta.LastModifiedDate
				}
				if maxCVSSv3.Score < meta.CVSSv3.Score {
					maxCVSSv3 = meta.CVSSv3
				}
				if maxCVSSv2.Score < meta.CVSSv2.Score {
					maxCVSSv2 = meta.CVSSv2
				}
			}
		}

		severity := fixSeverityScore(app.Severity, &maxCVSSv2, &maxCVSSv3)

		app.Severity = severity
		app.ScoreV3 = maxCVSSv3.Score
		app.VectorsV3 = maxCVSSv3.Vectors
		app.Score = maxCVSSv2.Score
		app.Vectors = maxCVSSv2.Vectors

		if !IgnoreSeverity(app.Severity) {
			outApps = append(outApps, app)
		}
	}

	return outVuls, outApps
}

// fetch get data from the registered fetchers, in parallel.
func fetch(datastore Datastore) (bool, []*Vulnerability, []*common.AppModuleVul, []*RawFile) {
	status := true

	status, osVuls := fetchDistroVul()
	if !status {
		return status, nil, nil, nil
	}

	status, rawFiles := fetchRawData()
	if !status {
		return status, nil, nil, nil
	}

	status, appVuls := fetchAppVul()
	if !status {
		return status, nil, nil, nil
	}

	if err := nvd.NVD.Load(); err != nil {
		log.Errorf("an error occured when loading NVD: %s.", err)
		return false, nil, nil, nil
	}

	correctAppAffectedVersion(appVuls)

	vuls, apps := assignMetadata(osVuls, appVuls)

	return status, vuls, apps, rawFiles
}

func doVulnerabilitiesNamespacing(vulnerabilities []Vulnerability) []*Vulnerability {
	vulnerabilitiesMap := make(map[string]*Vulnerability)

	for _, v := range vulnerabilities {
		featureVersions := v.FixedIn
		v.FixedIn = []FeatureVersion{}

		for _, fv := range featureVersions {
			index := fv.Feature.Namespace + ":" + v.Name

			if vulnerability, ok := vulnerabilitiesMap[index]; !ok {
				newVulnerability := v
				newVulnerability.Namespace = fv.Feature.Namespace
				newVulnerability.FixedIn = []FeatureVersion{fv}

				vulnerabilitiesMap[index] = &newVulnerability
			} else {
				vulnerability.FixedIn = append(vulnerability.FixedIn, fv)
			}
		}
	}

	// Convert map into a slice.
	var response []*Vulnerability
	for _, vulnerability := range vulnerabilitiesMap {
		response = append(response, vulnerability)
	}

	return response
}
