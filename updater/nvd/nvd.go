// Copyright 2015 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nvd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/vul-dbgen/common"
)

const (
	jsonUrl      = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%s.json.gz"
	cveURLPrefix = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="

	nvdAPIkey      = "NVD_KEY"
	retryTimes     = 5
	timeFormat     = "2006-01-02T15:04Z"
	timeFormatNew  = "2006-01-02T15:04:05"
	resultsPerPage = 2000
)

type NVDMetadataFetcher struct {
	localPath string
	lock      sync.Mutex
	nvdkey    *string

	metadata map[string]common.NVDMetadata
}

type NvdCve struct {
	Cve struct {
		ID               string `json:"id"`
		PublishedDate    string `json:"published"`
		LastModifiedDate string `json:"lastModified"`
		VulnStatus       string `json:"vulnStatus"`
		Description      []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"descriptions"`
		Metrics struct {
			BaseMetricV31 []struct {
				CvssData            CvssData `json:"cvssData"`
				ExploitabilityScore float64  `json:"exploitabilityScore"`
				ImpactScore         float64  `json:"impactScore"`
			} `json:"cvssMetricV31"`
			BaseMetricV3 []struct {
				CvssData            CvssData `json:"cvssData"`
				ExploitabilityScore float64  `json:"exploitabilityScore"`
				ImpactScore         float64  `json:"impactScore"`
			} `json:"cvssMetricV30"`
			BaseMetricV2 []struct {
				Source                  string   `json:"source"`
				Type                    string   `json:"type"`
				CvssData                CvssData `json:"cvssData"`
				Severity                string   `json:"severity"`
				ExploitabilityScore     float64  `json:"exploitabilityScore"`
				ImpactScore             float64  `json:"impactScore"`
				ObtainAllPrivilege      bool     `json:"obtainAllPrivilege"`
				ObtainUserPrivilege     bool     `json:"obtainUserPrivilege"`
				ObtainOtherPrivilege    bool     `json:"obtainOtherPrivilege"`
				UserInteractionRequired bool     `json:"userInteractionRequired"`
			} `json:"cvssMetricV2"`
		} `json:"metrics"`
		References []struct {
			URL       string `json:"url"`
			Refsource string `json:"source"`
		} `json:"references"`
		Configurations []struct {
			Nodes []struct {
				Operator string `json:"operator"`
				Negate   bool   `json:"negate"`
				CpeMatch []struct {
					Criteria              string `json:"criteria"`
					MatchCriteriaID       string `json:"matchCriteriaId"`
					Vulnerable            bool   `json:"vulnerable"`
					VersionStartIncluding string `json:"versionStartIncluding"`
					VersionStartExcluding string `json:"versionStartExcluding"`
					VersionEndIncluding   string `json:"versionEndIncluding"`
					VersionEndExcluding   string `json:"versionEndExcluding"`
				} `json:"cpeMatch"`
			} `json:"nodes"`
		} `json:"configurations"`
	} `json:"cve"`
}

type NvdData struct {
	StartIndex        int      `json:"startIndex"`
	TotalResultsCount int      `json:"totalResults"`
	CVEItems          []NvdCve `json:"vulnerabilities"`
	DataFormat        string   `json:"format"`
	DataVersion       string   `json:"version"`
}

type CvssData struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	AccessVector          string  `json:"accessVector"`
	AccessComplexity      string  `json:"accessComplexity"`
	Authentication        string  `json:"authentication"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore"`
}

var NVD NVDMetadataFetcher

func (fetcher *NVDMetadataFetcher) Load() error {
	fetcher.lock.Lock()
	defer fetcher.lock.Unlock()
	nvdKey := os.Getenv(nvdAPIkey)

	results := NvdData{}
	totalResults := 1
	index := 0

	var err error
	fetcher.metadata = make(map[string]common.NVDMetadata)

	// Init if necessary.
	if fetcher.localPath == "" {
		// Create a temporary folder to store the NVD data and create hashes struct.
		if fetcher.localPath, err = ioutil.TempDir(os.TempDir(), "nvd-data"); err != nil {
			return common.ErrFilesystem
		}
	}

	//default rate
	nvdDelay := time.Second * 6

	for index <= totalResults {
		newUrl := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=%d&startIndex=%d", resultsPerPage, index)
		currentBatch := NvdData{}
		fmt.Println(newUrl)
		client := &http.Client{}

		retry := 0
		for retry <= retryTimes {
			// json
			request, err := http.NewRequest("GET", newUrl, nil)
			if err != nil {
				log.WithFields(log.Fields{"err": err}).Error("Error in newLoad")
			}
			// use faster rate if apikey exists.
			if nvdKey != "" {
				request.Header.Set("apiKey", nvdKey)
				nvdDelay = time.Second
			}

			result, err := client.Do(request)
			if err != nil {
				log.WithFields(log.Fields{"err": err}).Error("Error in newLoad")
			}
			defer result.Body.Close()
			if err != nil {
				if retry == retryTimes {
					log.Errorf("Failed to get NVD json '%s': %s", newUrl, err)
					return common.ErrCouldNotDownload
				}
				retry++
				log.WithFields(log.Fields{"error": err, "retry": retry}).Error("Failed to get NVD data")
				continue
			}
			err = json.NewDecoder(result.Body).Decode(&currentBatch)
			if err != nil {
				log.WithFields(log.Fields{"err": err}).Error("Error in newLoad unmarshal")
			}
			if index == 0 {
				results = currentBatch
				totalResults = results.TotalResultsCount
			} else {
				results.CVEItems = append(results.CVEItems, currentBatch.CVEItems...)
			}
			index += resultsPerPage
			time.Sleep(nvdDelay)
			break
		}

	}
	for index, cve := range results.CVEItems {
		if index%2000 == 0 {
			log.WithFields(log.Fields{"index": index}).Debug("Index finished")
		}
		var meta common.NVDMetadata
		if len(cve.Cve.Description) > 0 {
			meta.Description = cve.Cve.Description[0].Value
		}
		if cve.Cve.ID != "" {
			//Prefer CVSS31 over CVSS30 if it exists.
			if len(cve.Cve.Metrics.BaseMetricV31) > 0 && cve.Cve.Metrics.BaseMetricV31[0].CvssData.BaseScore != 0 {
				meta.CVSSv3.Vectors = cve.Cve.Metrics.BaseMetricV31[0].CvssData.VectorString
				meta.CVSSv3.Score = cve.Cve.Metrics.BaseMetricV31[0].CvssData.BaseScore
			} else if len(cve.Cve.Metrics.BaseMetricV3) > 0 && cve.Cve.Metrics.BaseMetricV3[0].CvssData.BaseScore != 0 {
				meta.CVSSv3.Vectors = cve.Cve.Metrics.BaseMetricV3[0].CvssData.VectorString
				meta.CVSSv3.Score = cve.Cve.Metrics.BaseMetricV3[0].CvssData.BaseScore
			}
			if len(cve.Cve.Metrics.BaseMetricV31) > 0 && cve.Cve.Metrics.BaseMetricV31[0].CvssData.BaseScore != 0 {
				meta.CVSSv2.Vectors = cve.Cve.Metrics.BaseMetricV31[0].CvssData.VectorString
				meta.CVSSv2.Score = cve.Cve.Metrics.BaseMetricV31[0].CvssData.BaseScore
			} else if len(cve.Cve.Metrics.BaseMetricV3) > 0 && cve.Cve.Metrics.BaseMetricV3[0].CvssData.BaseScore != 0 {
				meta.CVSSv2.Vectors = cve.Cve.Metrics.BaseMetricV3[0].CvssData.VectorString
				meta.CVSSv2.Score = cve.Cve.Metrics.BaseMetricV3[0].CvssData.BaseScore
			}
			if cve.Cve.PublishedDate != "" {
				// Use new format, try old format if parse fails.
				if t, err := time.Parse(timeFormatNew, cve.Cve.LastModifiedDate); err == nil {
					meta.PublishedDate = t
				} else if t, err := time.Parse(timeFormat, cve.Cve.LastModifiedDate); err == nil {
					meta.PublishedDate = t
				}
			}
			if cve.Cve.LastModifiedDate != "" {
				// Use new format, try old format if parse fails.
				if t, err := time.Parse(timeFormatNew, cve.Cve.LastModifiedDate); err == nil {
					meta.LastModifiedDate = t
				} else if t, err := time.Parse(timeFormat, cve.Cve.LastModifiedDate); err == nil {
					meta.LastModifiedDate = t
				}
			}

			meta.VulnVersions = make([]common.NVDvulnerableVersion, 0)
			if len(cve.Cve.Configurations) > 0 {
				for _, node := range cve.Cve.Configurations[0].Nodes {
					if node.Operator == "OR" && len(node.CpeMatch) > 0 {
						for _, m := range node.CpeMatch {
							if m.Vulnerable &&
								// TODO: explicitly ignore microsoft:visual_studio_, as it is often confused with .net core version
								!strings.Contains(m.Criteria, "microsoft:visual_studio_") &&
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
			}

			fetcher.metadata[cve.Cve.ID] = meta
		}
	}
	return nil
}

func (fetcher *NVDMetadataFetcher) GetMetadata(cve string) (*common.NVDMetadata, bool) {
	if nvd, ok := fetcher.metadata[cve]; ok {
		var description string
		if nvd.Description == "" {
			description = getCveDescription(cve)
		} else {
			description = nvd.Description
		}
		return &common.NVDMetadata{
			Description:      description,
			CVSSv3:           nvd.CVSSv3,
			CVSSv2:           nvd.CVSSv2,
			PublishedDate:    nvd.PublishedDate,
			LastModifiedDate: nvd.LastModifiedDate,
		}, true
	} else {
		return nil, false
	}
}

// Return affected version and fixed version
func (fetcher *NVDMetadataFetcher) GetAffectedVersion(name string) ([]string, []string, bool) {
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