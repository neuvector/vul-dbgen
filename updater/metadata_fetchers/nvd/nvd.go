package nvd

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/vul-dbgen/common"
	"github.com/vul-dbgen/updater"
	"github.com/vul-dbgen/share"
)

const (
	jsonUrl      = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%s.json.gz"
	cveURLPrefix = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="

	metadataKey string = "NVD"
	retryTimes         = 5
	startYear          = 2012
	timeFormat         = "2006-01-02T15:04Z"
)

type NVDMetadataFetcher struct {
	localPath string
	lock      sync.Mutex

	metadata map[string]common.NVDMetadata
}

type NvdCve struct {
	Cve struct {
		DataType    string `json:"data_type"`
		DataFormat  string `json:"data_format"`
		DataVersion string `json:"data_version"`
		CVEDataMeta struct {
			ID       string `json:"ID"`
			ASSIGNER string `json:"ASSIGNER"`
		} `json:"CVE_data_meta"`
		Affects struct {
			Vendor struct {
				VendorData []struct {
					VendorName string `json:"vendor_name"`
					Product    struct {
						ProductData []struct {
							ProductName string `json:"product_name"`
							Version     struct {
								VersionData []struct {
									VersionValue    string `json:"version_value"`
									VersionAffected string `json:"version_affected"`
								} `json:"version_data"`
							} `json:"version"`
						} `json:"product_data"`
					} `json:"product"`
				} `json:"vendor_data"`
			} `json:"vendor"`
		} `json:"affects"`
		Problemtype struct {
			ProblemtypeData []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"problemtype_data"`
		} `json:"problemtype"`
		References struct {
			ReferenceData []struct {
				URL       string        `json:"url"`
				Name      string        `json:"name"`
				Refsource string        `json:"refsource"`
				Tags      []interface{} `json:"tags"`
			} `json:"reference_data"`
		} `json:"references"`
		Description struct {
			DescriptionData []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"description_data"`
		} `json:"description"`
	} `json:"cve"`
	Configurations struct {
		CVEDataVersion string `json:"CVE_data_version"`
		Nodes          []struct {
			Operator string `json:"operator"`
			CpeMatch []struct {
				Vulnerable            bool   `json:"vulnerable"`
				Cpe23URI              string `json:"cpe23Uri"`
				VersionStartIncluding string `json:"versionStartIncluding"`
				VersionStartExcluding string `json:"versionStartExcluding"`
				VersionEndIncluding   string `json:"versionEndIncluding"`
				VersionEndExcluding   string `json:"versionEndExcluding"`
			} `json:"cpe_match"`
		} `json:"nodes"`
	} `json:"configurations"`
	Impact struct {
		BaseMetricV3 struct {
			CvssV3 struct {
				Version               string  `json:"version"`
				VectorString          string  `json:"vectorString"`
				AttackVector          string  `json:"attackVector"`
				AttackComplexity      string  `json:"attackComplexity"`
				PrivilegesRequired    string  `json:"privilegesRequired"`
				UserInteraction       string  `json:"userInteraction"`
				Scope                 string  `json:"scope"`
				ConfidentialityImpact string  `json:"confidentialityImpact"`
				IntegrityImpact       string  `json:"integrityImpact"`
				AvailabilityImpact    string  `json:"availabilityImpact"`
				BaseScore             float64 `json:"baseScore"`
				BaseSeverity          string  `json:"baseSeverity"`
			} `json:"cvssV3"`
			ExploitabilityScore float64 `json:"exploitabilityScore"`
			ImpactScore         float64 `json:"impactScore"`
		} `json:"baseMetricV3"`
		BaseMetricV2 struct {
			CvssV2 struct {
				Version               string  `json:"version"`
				VectorString          string  `json:"vectorString"`
				AccessVector          string  `json:"accessVector"`
				AccessComplexity      string  `json:"accessComplexity"`
				Authentication        string  `json:"authentication"`
				ConfidentialityImpact string  `json:"confidentialityImpact"`
				IntegrityImpact       string  `json:"integrityImpact"`
				AvailabilityImpact    string  `json:"availabilityImpact"`
				BaseScore             float64 `json:"baseScore"`
			} `json:"cvssV2"`
			Severity                string  `json:"severity"`
			ExploitabilityScore     float64 `json:"exploitabilityScore"`
			ImpactScore             float64 `json:"impactScore"`
			ObtainAllPrivilege      bool    `json:"obtainAllPrivilege"`
			ObtainUserPrivilege     bool    `json:"obtainUserPrivilege"`
			ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege"`
			UserInteractionRequired bool    `json:"userInteractionRequired"`
		} `json:"baseMetricV2"`
	} `json:"impact"`
	PublishedDate    string `json:"publishedDate"`
	LastModifiedDate string `json:"lastModifiedDate"`
}

type NvdData struct {
	CVEDataType         string   `json:"CVE_data_type"`
	CVEDataFormat       string   `json:"CVE_data_format"`
	CVEDataVersion      string   `json:"CVE_data_version"`
	CVEDataNumberOfCVEs string   `json:"CVE_data_numberOfCVEs"`
	CVEDataTimestamp    string   `json:"CVE_data_timestamp"`
	CVEItems            []NvdCve `json:"CVE_Items"`
}

func init() {
	updater.RegisterMetadataFetcher("NVD", &NVDMetadataFetcher{})
}

func (fetcher *NVDMetadataFetcher) Load(datastore updater.Datastore) error {
	fetcher.lock.Lock()
	defer fetcher.lock.Unlock()

	var err error
	fetcher.metadata = make(map[string]common.NVDMetadata)

	// Init if necessary.
	if fetcher.localPath == "" {
		// Create a temporary folder to store the NVD data and create hashes struct.
		if fetcher.localPath, err = ioutil.TempDir(os.TempDir(), "nvd-data"); err != nil {
			return common.ErrFilesystem
		}
	}
	defer os.RemoveAll(fetcher.localPath)

	// Get data feeds.
	for y := startYear; y <= time.Now().Year(); y++ {
		dataFeedName := strconv.Itoa(y)

		retry := 0
		for retry <= retryTimes {
			// json
			r, err := http.Get(fmt.Sprintf(jsonUrl, dataFeedName))
			if err != nil {
				if retry == retryTimes {
					log.Errorf("Failed to download NVD data feed file '%s': %s", dataFeedName, err)
					return common.ErrCouldNotDownload
				}
				retry++
				log.WithFields(log.Fields{"error": err, "retry": retry}).Debug("Failed to get NVD data")
				continue
			}

			// Un-gzip it.
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				if retry == retryTimes {
					log.Errorf("Failed to read NVD data feed file '%s': %s", dataFeedName, err)
					return common.ErrCouldNotDownload
				}
				retry++
				log.WithFields(log.Fields{"error": err, "retry": retry}).Debug("Failed to ungzip NVD data")
				continue
			}
			jsonData := utils.GunzipBytes(body)

			var nvdData NvdData
			err = json.Unmarshal(jsonData, &nvdData)
			if err != nil {
				log.Errorf("Failed to unmarshal NVD data feed file '%s': %s", dataFeedName, err)
				return common.ErrCouldNotDownload
			}
			for _, cve := range nvdData.CVEItems {
				var meta common.NVDMetadata
				if len(cve.Cve.Description.DescriptionData) > 0 {
					meta.Description = cve.Cve.Description.DescriptionData[0].Value
				}
				if cve.Cve.CVEDataMeta.ID != "" {
					if cve.Impact.BaseMetricV3.CvssV3.BaseScore != 0 {
						meta.CVSSv3.Vectors = cve.Impact.BaseMetricV3.CvssV3.VectorString
						meta.CVSSv3.Score = cve.Impact.BaseMetricV3.CvssV3.BaseScore
					}
					if cve.Impact.BaseMetricV2.CvssV2.BaseScore != 0 {
						meta.CVSSv2.Vectors = cve.Impact.BaseMetricV2.CvssV2.VectorString
						meta.CVSSv2.Score = cve.Impact.BaseMetricV2.CvssV2.BaseScore
					}
					if cve.PublishedDate != "" {
						if t, err := time.Parse(timeFormat, cve.PublishedDate); err == nil {
							meta.PublishedDate = t
						}
					}
					if cve.LastModifiedDate != "" {
						if t, err := time.Parse(timeFormat, cve.LastModifiedDate); err == nil {
							meta.LastModifiedDate = t
						}
					}

					meta.VulnVersions = make([]common.NVDvulnerableVersion, 0)
					for _, node := range cve.Configurations.Nodes {
						if node.Operator == "OR" && len(node.CpeMatch) > 0 {
							for _, m := range node.CpeMatch {
								if m.Vulnerable &&
									// TODO: explicitly ignore microsoft:visual_studio_, as it is often confused with .net core version
									!strings.Contains(m.Cpe23URI, "microsoft:visual_studio_") &&
									(m.VersionStartIncluding != "" ||
										m.VersionStartExcluding != "" ||
										m.VersionEndIncluding != "" ||
										m.VersionEndExcluding != "") {
									meta.VulnVersions = append(meta.VulnVersions, common.NVDvulnerableVersion{
										StartIncluding: m.VersionStartIncluding,
										StartExcluding: m.VersionStartExcluding,
										EndIncluding:   m.VersionEndIncluding,
										EndExcluding:   m.VersionEndExcluding,
									})
								}
							}
						}
					}

					fetcher.metadata[cve.Cve.CVEDataMeta.ID] = meta

					// log.WithFields(log.Fields{"cve": cve.Cve.CVEDataMeta.ID, "v3": meta.CVSSv3.Score}).Info()
				}
			}

			log.WithFields(log.Fields{"year": dataFeedName, "count": len(nvdData.CVEItems)}).Info()
			break
		}
	}

	return nil
}

var redhatCveRegexp = regexp.MustCompile(`\(CVE-([0-9]+)-([0-9]+)`)

func (fetcher *NVDMetadataFetcher) AddMetadata(v *updater.VulnerabilityWithLock) error {
	fetcher.lock.Lock()
	defer fetcher.lock.Unlock()

	cves := []updater.CVE{updater.CVE{Name: v.Name}}
	if len(v.CVEs) > 0 {
		cves = v.CVEs
	}

	var maxV2, maxV3 float64
	var found bool

	v.Lock.Lock()
	defer v.Lock.Unlock()
	for _, cve := range cves {
		nvd, ok := fetcher.metadata[cve.Name]
		if !ok {
			nvd = common.NVDMetadata{
				CVSSv2:           common.CVSS{Vectors: cve.CVSSv2.Vectors, Score: cve.CVSSv2.Score},
				CVSSv3:           common.CVSS{Vectors: cve.CVSSv3.Vectors, Score: cve.CVSSv3.Score},
				PublishedDate:    v.Vulnerability.IssuedDate,
				LastModifiedDate: v.Vulnerability.LastModDate,
			}
		}

		found = true

		// Create Metadata map if necessary.
		if v.Metadata == nil {
			v.Metadata = make(map[string]interface{})
		}

		if v.Vulnerability.Description == "" {
			if nvd.Description == "" {
				v.Vulnerability.Description = getCveDescription(v.Vulnerability.Name)
			} else {
				v.Vulnerability.Description = nvd.Description
			}
		}

		// Redhat and Amazon fetcher retrieves issued date
		if v.Vulnerability.IssuedDate.IsZero() {
			v.Vulnerability.IssuedDate = nvd.PublishedDate
		}
		if v.Vulnerability.LastModDate.IsZero() {
			v.Vulnerability.LastModDate = nvd.LastModifiedDate
		}

		if nvd.CVSSv3.Score > maxV3 {
			maxV3 = nvd.CVSSv3.Score
			maxV2 = nvd.CVSSv2.Score
			v.Metadata[metadataKey] = nvd
			continue
		} else if nvd.CVSSv3.Score < maxV3 {
			continue
		}
		if nvd.CVSSv2.Score > maxV2 {
			maxV3 = nvd.CVSSv3.Score
			maxV2 = nvd.CVSSv2.Score
			v.Metadata[metadataKey] = nvd
		}
	}

	// if v.Vulnerability.Name == "CVE-2021-3426" {
	// 	log.WithFields(log.Fields{"v": v.Vulnerability}).Error("================")
	// }

	if found {
		// log.WithFields(log.Fields{"cve": v.Name, "maxV2": maxV2, "maxV3": maxV3}).Info()

		// For NVSHAS-4709, always set the severity by CVSS scores
		// if v.Vulnerability.Severity == common.Unknown || v.Vulnerability.Severity == "" {
		// similar logic in app fetchers
		if maxV3 >= 7 || maxV2 >= 7 {
			v.Vulnerability.Severity = common.High
		} else if maxV3 >= 4 || maxV2 >= 4 {
			v.Vulnerability.Severity = common.Medium
		} else {
			v.Vulnerability.Severity = common.Low
		}
	} else {
		if v.Vulnerability.Description == "" {
			v.Vulnerability.Description = getCveDescription(v.Vulnerability.Name)
		}
	}

	return nil
}

func (fetcher *NVDMetadataFetcher) AddCveDate(name string) (time.Time, time.Time, bool) {
	fetcher.lock.Lock()
	defer fetcher.lock.Unlock()

	if nvd, ok := fetcher.metadata[name]; ok {
		return nvd.PublishedDate, nvd.LastModifiedDate, true
	}

	return time.Time{}, time.Time{}, false
}

// Return affected version and fixed version
func (fetcher *NVDMetadataFetcher) AddAffectedVersion(name string) ([]string, []string, bool) {
	fetcher.lock.Lock()
	defer fetcher.lock.Unlock()

	if nvd, ok := fetcher.metadata[name]; ok {
		affects := make([]string, 0)
		fixes := make([]string, 0)
		opAffect := ""
		opFix := ""
		for _, v := range nvd.VulnVersions {
			if v.StartIncluding != "" {
				affects = append(affects, fmt.Sprintf("%s>=%s", opAffect, v.StartIncluding))
				opAffect = ""
			} else if v.StartExcluding != "" {
				affects = append(affects, fmt.Sprintf("%s>%s", opAffect, v.StartExcluding))
				opAffect = ""
			}
			if v.EndIncluding != "" {
				affects = append(affects, fmt.Sprintf("%s<=%s", opAffect, v.EndIncluding))
				fixes = append(fixes, fmt.Sprintf("%s>%s", opFix, v.EndIncluding))
			} else if v.EndExcluding != "" {
				affects = append(affects, fmt.Sprintf("%s<%s", opAffect, v.EndExcluding))
				fixes = append(fixes, fmt.Sprintf("%s>=%s", opFix, v.EndExcluding))
			}
			opAffect = "||"
			opFix = "||"
		}
		return affects, fixes, true
	}

	return nil, nil, false
}

func (fetcher *NVDMetadataFetcher) LookupMetadata(name string) (string, float64, string, float64, bool) {
	fetcher.lock.Lock()
	defer fetcher.lock.Unlock()

	if nvd, ok := fetcher.metadata[name]; ok {
		return nvd.CVSSv2.Vectors, nvd.CVSSv2.Score, nvd.CVSSv3.Vectors, nvd.CVSSv3.Score, true
	}

	return "", 0, "", 0, false
}

func (fetcher *NVDMetadataFetcher) Unload() {
	fetcher.lock.Lock()
	defer fetcher.lock.Unlock()

	fetcher.metadata = nil
	os.RemoveAll(fetcher.localPath)
}

func (fetcher *NVDMetadataFetcher) Clean() {
	fetcher.lock.Lock()
	defer fetcher.lock.Unlock()

	os.RemoveAll(fetcher.localPath)
}

func getHashFromMetaURL(metaURL string) (string, error) {
	r, err := http.Get(metaURL)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()

	scanner := bufio.NewScanner(r.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "sha256:") {
			return strings.TrimPrefix(line, "sha256:"), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", errors.New("invalid .meta file format")
}

func getCveDescription(cve string) string {
	var description string
	url := cveURLPrefix + cve
	r, err := http.Get(url)
	if err != nil {
		log.WithFields(log.Fields{"cve": cve}).Error("no nvd data")
		return description
	}
	defer r.Body.Close()

	var descEnable, descStart bool
	scanner := bufio.NewScanner(r.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if descEnable {
			if strings.Contains(line, "<td colspan=") {
				descStart = true
			}
			if descStart && !strings.Contains(line, "<A HREF=") {
				if i := strings.Index(line, "\">"); i > 0 {
					description += line[i+2:]
				} else if strings.Contains(line, "</td>") {
					return description
				} else {
					description += line
				}
				if len(description) > 0 && description[len(description)-1] != '.' {
					description += " "
				}
			}
		}
		if strings.Contains(line, ">Description</th>") {
			descEnable = true
		}
	}
	return description
}
