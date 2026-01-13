package alpine

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/vul-dbgen/common"
	"github.com/vul-dbgen/updater"
)

const (
	retryAttempts = 5
	retryTime     = 2000
)

var (
	photonFiles []photonFile = []photonFile{
		photonFile{"photon/cve_data_photon1.0.json.gz", 1},
		photonFile{"photon/cve_data_photon2.0.json.gz", 2},
		photonFile{"photon/cve_data_photon3.0.json.gz", 3},
		photonFile{"photon/cve_data_photon4.0.json.gz", 4},
		photonFile{"photon/cve_data_photon5.0.json.gz", 5},
	}

	alternatePackageNames = map[string]string{
		"expat": "expat-libs",
	}
)

var photonSecurityAdvisories = []string{"https://packages.vmware.com/photon/photon_cve_metadata/cve_data_photon1.0.json"}

type PhotonFetcher struct{}

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
type jsonVulns struct {
	Vulns []jsonVuln
}

type jsonVuln struct {
	CveId           string  `json:"cve_id"`
	Package         string  `json:"pkg"`
	CveScore        float64 `json:"cve_score"`
	ResolvedVersion string  `json:"res_ver"`
}

type photonFile struct {
	Name    string
	Version float64
}

func init() {
	updater.RegisterFetcher("photon", &PhotonFetcher{})
}

func (f *PhotonFetcher) FetchUpdate() (resp updater.FetcherResponse, err error) {
	log.WithField("package", "Photon").Info("Start fetching vulnerabilities")
	//f.fetchRemote()
	vulns, err := f.fetchLocal(photonFiles)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Debug("Error fetching photon update.")
	}

	for _, vul := range vulns {
		//key := fmt.Sprintf("%s:%s", vul.FixedIn[0].Feature.Namespace, vul.Name)
		resp.Vulnerabilities = append(resp.Vulnerabilities, vul)
	}

	log.WithFields(log.Fields{"Vulnerabilities": len(resp.Vulnerabilities)}).Info("fetching photon done")
	return resp, nil
}

func (f *PhotonFetcher) fetchLocal(files []photonFile) ([]common.Vulnerability, error) {
	results := []common.Vulnerability{}
	for _, file := range files {
		dataFile := fmt.Sprintf("%s%s", common.CVESourceRoot, file.Name)
		f, err := os.Open(dataFile)
		if err != nil {
			log.WithFields(log.Fields{"file": dataFile}).Error("Cannot find local database")
			return results, err
		}

		defer f.Close()

		gzr, err := gzip.NewReader(f)
		if err != nil {
			log.WithFields(log.Fields{"file": dataFile}).Error("Failed to create feed reader")
			return results, err
		}
		defer gzr.Close()

		var r []jsonVuln

		err = json.NewDecoder(gzr).Decode(&r)
		if err != nil {
			return results, err
		}

		for _, vuln := range r {
			namespace := fmt.Sprintf("photon:%v", file.Version)
			if vuln.ResolvedVersion == "N/A" || vuln.ResolvedVersion == "NA" {
				vuln.ResolvedVersion = common.MaxVersion.String()
			}
			version, err2 := common.NewVersion(vuln.ResolvedVersion)
			if err != nil {
				log.WithFields(log.Fields{"err": err2, "vuln": vuln.CveId}).Info("Unable to resolve version for photon vulnerability.")
				continue
			}
			currentVuln := common.Vulnerability{
				Name:      vuln.CveId,
				Namespace: namespace,
				Severity:  "",
				CVSSv2:    common.CVSS{},
				CVSSv3: common.CVSS{
					Score: vuln.CveScore,
				},
				CVEs: []common.CVE{},
				FixedIn: []common.FeatureVersion{
					{
						Name: vuln.Package,
						Feature: common.Feature{
							Name:      vuln.Package,
							Namespace: namespace,
						},
						Version: version,
					},
				},
				CPEs:       []string{},
				FeedRating: "",
			}
			//If alternate name exists for a fixedin entry, add the alternate name as an additional fixedin entry.
			for _, fixedIn := range currentVuln.FixedIn {
				if val, ok := alternatePackageNames[fixedIn.Name]; ok {
					alternateEntry := common.FeatureVersion{
						Name: val,
						Feature: common.Feature{
							Name:      val,
							Namespace: namespace,
						},
						Version: version,
					}
					currentVuln.FixedIn = append(currentVuln.FixedIn, alternateEntry)
				}
			}

			results = append(results, currentVuln)
		}
	}
	return results, nil
}

func (f *PhotonFetcher) Clean() {}
