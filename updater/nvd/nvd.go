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
	"bytes"
	"compress/gzip"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	bolt "go.etcd.io/bbolt"

	"github.com/vul-dbgen/common"
)

const (
	cveURLPrefix = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="

	nvdAPIkey      = "NVD_KEY"
	nvdSubfolder   = "nvd"
	nvdDBName      = "nvd_bbolt.db"
	nvdBucketName  = "nvd"
	retryTimes     = 5
	timeFormat     = "2006-01-02T15:04Z"
	timeFormatNew  = "2006-01-02T15:04:05"
	resultsPerPage = 2000
	batchSize      = 5000
	maxErrorBody   = 4096
)

type NVDMetadataFetcher struct {
	nvdkey      *string
	dbPath      string
	db          *bolt.DB
	batchWriter *batchWriter
}

// StoredNVDData is what we store in bbolt (includes everything)
type StoredNVDData struct {
	Description      string
	Severity         common.Priority
	CVSSv2           common.CVSS
	CVSSv3           common.CVSS
	PublishedDate    time.Time
	LastModifiedDate time.Time
	Link             string
	VulnVersions     []common.NVDvulnerableVersion
}

// batchWriter accumulates writes and flushes in batches for better performance
type batchWriter struct {
	batch map[string][]byte
	db    *bolt.DB
	size  int
}

func newBatchWriter(db *bolt.DB) *batchWriter {
	return &batchWriter{
		batch: make(map[string][]byte, batchSize),
		db:    db,
		size:  0,
	}
}

func (bw *batchWriter) add(key string, value []byte) error {
	bw.batch[key] = value
	bw.size++

	if bw.size >= batchSize {
		return bw.flush()
	}
	return nil
}

func (bw *batchWriter) flush() error {
	if len(bw.batch) == 0 {
		return nil
	}

	err := bw.db.Batch(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(nvdBucketName))
		for k, v := range bw.batch {
			if err := b.Put([]byte(k), v); err != nil {
				return err
			}
		}
		return nil
	})

	if err == nil {
		bw.batch = make(map[string][]byte, batchSize)
		bw.size = 0
	}

	return err
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
				Severity                string   `json:"baseSeverity"`
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
	BaseSeverity          string  `json:"baseSeverity"`
}

var NVD NVDMetadataFetcher

func (fetcher *NVDMetadataFetcher) initDB() error {
	tmpDir := os.Getenv("NVD_TMP_PATH")
	if tmpDir == "" {
		tmpDir = os.TempDir()
	}

	fetcher.dbPath = filepath.Join(tmpDir, nvdDBName)
	os.Remove(fetcher.dbPath)

	db, err := bolt.Open(fetcher.dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return fmt.Errorf("failed to open bbolt: %w", err)
	}

	fetcher.db = db

	// Create bucket
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(nvdBucketName))
		return err
	})

	if err != nil {
		db.Close()
		return fmt.Errorf("failed to create bucket: %w", err)
	}

	// Initialize batch writer
	fetcher.batchWriter = newBatchWriter(db)

	log.WithField("path", fetcher.dbPath).Info("Initialized NVD bbolt database")
	return nil
}

func (fetcher *NVDMetadataFetcher) loadPreDownload(folder string) (*NvdData, error) {
	files, err := findPreDownloadFiles(folder)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no NVD predownload files found")
	}

	var count int
	for _, file := range files {
		log.WithFields(log.Fields{"file": file}).Info("Read NVD data")

		if err := streamPreDownloadFile(file, func(cve NvdCve) error {
			if err := fetcher.storeMetadata(cve); err != nil {
				return err
			}
			count++
			if count%50000 == 0 {
				common.LogMemStats(fmt.Sprintf("nvd-preload-%d", count))
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	log.WithField("count", count).Info("Loaded NVD predownload data")
	return nil, nil
}

func (fetcher *NVDMetadataFetcher) loadRemote() (*NvdData, error) {
	nvdKey := os.Getenv(nvdAPIkey)
	totalResults := 1
	index := 0

	//default rate
	nvdDelay := time.Second * 6

	for index <= totalResults {
		newUrl := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=%d&startIndex=%d", resultsPerPage, index)
		currentBatch := NvdData{}
		client := &http.Client{}

		retry := 0
		for retry <= retryTimes {
			// json
			request, err := http.NewRequest("GET", newUrl, nil)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Error in retrieving from url")
			}
			// use faster rate if apikey exists.
			if nvdKey != "" {
				request.Header.Set("apiKey", nvdKey)
				nvdDelay = time.Second
			}

			resp, err := client.Do(request)
			if err != nil {
				log.WithFields(log.Fields{"error": err, "retry": retry}).Error("Failed to get NVD data")
				if retry == retryTimes {
					log.Errorf("Failed to get NVD json '%s': %s", newUrl, err)
					return nil, err
				}
				retry++
			} else {
				err = json.NewDecoder(resp.Body).Decode(&currentBatch)
				if err != nil {
					log.WithFields(log.Fields{"error": err}).Error("Error in during unmarshal")
				} else {
					if index == 0 {
						totalResults = currentBatch.TotalResultsCount
					}
					for _, cve := range currentBatch.CVEItems {
						if err := fetcher.storeMetadata(cve); err != nil {
							log.WithFields(log.Fields{"cve": cve.Cve.ID, "error": err}).Warn("Failed to store CVE, skipping")
						}
					}
					index += resultsPerPage
				}
				time.Sleep(nvdDelay)
				resp.Body.Close()
				break
			}
		}
	}

	return nil, nil
}

func (fetcher *NVDMetadataFetcher) Load() error {
	// Initialize bbolt database
	if err := fetcher.initDB(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to initialize NVD database")
		return common.ErrCouldNotDownload
	}

	// Load data from files or remote API
	var err error
	nvdFolder := filepath.Join(common.CVESourceRoot, nvdSubfolder)

	log.WithFields(log.Fields{"hasPreDownloadFiles(nvdFolder) ": hasPreDownloadFiles(nvdFolder), "hasMergedPreDownloadFiles()": hasMergedPreDownloadFiles()}).Info("xxxxx Loading NVD data")
	if hasPreDownloadFiles(nvdFolder) || hasMergedPreDownloadFiles() {
		_, err = fetcher.loadPreDownload(nvdFolder)
	} else {
		_, err = fetcher.loadRemote()
	}

	// Flush any remaining batched writes
	var flushErr error
	if fetcher.batchWriter != nil {
		flushErr = fetcher.batchWriter.flush()
	}

	if err != nil || flushErr != nil {
		log.WithFields(log.Fields{"loadErr": err, "flushErr": flushErr}).Error("NVD load failed")
		return common.ErrCouldNotDownload
	}

	return nil
}

func decodeNVDResponse(resp *http.Response) (*NvdData, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	contentType := resp.Header.Get("Content-Type")
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d content-type=%q body=%q", resp.StatusCode, contentType, trimForLog(body))
	}
	if contentType != "" && !strings.Contains(strings.ToLower(contentType), "application/json") {
		return nil, fmt.Errorf("unexpected content-type %q body=%q", contentType, trimForLog(body))
	}

	var currentBatch NvdData
	if err := json.Unmarshal(body, &currentBatch); err != nil {
		return nil, fmt.Errorf("decode json: %w body=%q", err, trimForLog(body))
	}

	return &currentBatch, nil
}

func trimForLog(body []byte) string {
	text := strings.TrimSpace(string(body))
	if len(text) > maxErrorBody {
		return text[:maxErrorBody] + "..."
	}
	return text
}

func hasPreDownloadFiles(folder string) bool {
	files, err := findPreDownloadFiles(folder)
	return err == nil && len(files) > 0
}

func hasMergedPreDownloadFiles() bool {
	for _, file := range mergedPreDownloadPaths() {
		if _, err := os.Stat(file); err == nil {
			return true
		}
	}
	return false
}

func mergedPreDownloadPaths() []string {
	return []string{
		filepath.Join(common.CVESourceRoot, "merged_nvd_feeds.json.gz"),
		filepath.Join(common.CVESourceRoot, "merged_nvd_feeds.json"),
		filepath.Join(common.CVESourceRoot, nvdSubfolder, "merged_nvd_feeds.json.gz"),
		filepath.Join(common.CVESourceRoot, nvdSubfolder, "merged_nvd_feeds.json"),
	}
}

func findPreDownloadFiles(folder string) ([]string, error) {
	for _, merged := range mergedPreDownloadPaths() {
		if _, err := os.Stat(merged); err == nil {
			return []string{merged}, nil
		}
	}

	files, err := os.ReadDir(folder)
	if err != nil {
		return nil, err
	}

	paths := make([]string, 0, len(files))
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".json.gz") || strings.HasSuffix(f.Name(), ".json") {
			paths = append(paths, filepath.Join(folder, f.Name()))
		}
	}
	sort.Strings(paths)
	return paths, nil
}

func streamPreDownloadFile(path string, onCVE func(NvdCve) error) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	var reader io.Reader = file
	if strings.HasSuffix(path, ".gz") {
		gzr, err := gzip.NewReader(file)
		if err != nil {
			return err
		}
		defer gzr.Close()
		reader = gzr
	}

	return streamVulnerabilities(reader, onCVE)
}

func streamVulnerabilities(reader io.Reader, onCVE func(NvdCve) error) error {
	decoder := json.NewDecoder(bufio.NewReaderSize(reader, 1024*1024))

	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return fmt.Errorf("unexpected NVD JSON start token: %v", token)
	}

	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("unexpected NVD JSON key token: %v", token)
		}

		if key != "vulnerabilities" {
			var discard json.RawMessage
			if err := decoder.Decode(&discard); err != nil {
				return err
			}
			continue
		}

		token, err = decoder.Token()
		if err != nil {
			return err
		}
		if delim, ok := token.(json.Delim); !ok || delim != '[' {
			return fmt.Errorf("unexpected vulnerabilities token: %v", token)
		}

		for decoder.More() {
			var cve NvdCve
			if err := decoder.Decode(&cve); err != nil {
				return err
			}
			if err := onCVE(cve); err != nil {
				return err
			}
		}

		if _, err := decoder.Token(); err != nil {
			return err
		}
	}

	_, err = decoder.Token()
	return err
}

func (fetcher *NVDMetadataFetcher) storeMetadata(cve NvdCve) error {
	var meta common.NVDMetadata
	if len(cve.Cve.Description) > 0 {
		meta.Description = cve.Cve.Description[0].Value
	}
	if cve.Cve.ID == "" {
		return nil
	}

	if len(cve.Cve.Metrics.BaseMetricV31) > 0 && cve.Cve.Metrics.BaseMetricV31[0].CvssData.BaseScore != 0 {
		meta.CVSSv3.Vectors = cve.Cve.Metrics.BaseMetricV31[0].CvssData.VectorString
		meta.CVSSv3.Score = cve.Cve.Metrics.BaseMetricV31[0].CvssData.BaseScore
		meta.Severity = fetcher.toSeverity(cve.Cve.Metrics.BaseMetricV31[0].CvssData.BaseSeverity)
	} else if len(cve.Cve.Metrics.BaseMetricV3) > 0 && cve.Cve.Metrics.BaseMetricV3[0].CvssData.BaseScore != 0 {
		meta.CVSSv3.Vectors = cve.Cve.Metrics.BaseMetricV3[0].CvssData.VectorString
		meta.CVSSv3.Score = cve.Cve.Metrics.BaseMetricV3[0].CvssData.BaseScore
		meta.Severity = fetcher.toSeverity(cve.Cve.Metrics.BaseMetricV3[0].CvssData.BaseSeverity)
	}
	if len(cve.Cve.Metrics.BaseMetricV2) > 0 && cve.Cve.Metrics.BaseMetricV2[0].CvssData.BaseScore != 0 {
		meta.CVSSv2.Vectors = cve.Cve.Metrics.BaseMetricV2[0].CvssData.VectorString
		meta.CVSSv2.Score = cve.Cve.Metrics.BaseMetricV2[0].CvssData.BaseScore
		if meta.Severity == "" {
			meta.Severity = fetcher.toSeverity(cve.Cve.Metrics.BaseMetricV2[0].Severity)
		}
	}
	if cve.Cve.PublishedDate != "" {
		if t, err := time.Parse(timeFormatNew, cve.Cve.PublishedDate); err == nil {
			meta.PublishedDate = t
		} else if t, err := time.Parse(timeFormat, cve.Cve.PublishedDate); err == nil {
			meta.PublishedDate = t
		}
	}
	if cve.Cve.LastModifiedDate != "" {
		if t, err := time.Parse(timeFormatNew, cve.Cve.LastModifiedDate); err == nil {
			meta.LastModifiedDate = t
		} else if t, err := time.Parse(timeFormat, cve.Cve.LastModifiedDate); err == nil {
			meta.LastModifiedDate = t
		}
	}
	meta.Link = cveURLPrefix + cve.Cve.ID

	meta.VulnVersions = make([]common.NVDvulnerableVersion, 0)
	if len(cve.Cve.Configurations) > 0 {
		for _, node := range cve.Cve.Configurations[0].Nodes {
			if node.Operator == "OR" && len(node.CpeMatch) > 0 {
				for _, m := range node.CpeMatch {
					if m.Vulnerable &&
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

	if common.Debugs.Enabled && common.Debugs.CVEs.Contains(cve.Cve.ID) {
		log.WithFields(log.Fields{
			"name": cve.Cve.ID, "v2": meta.CVSSv2.Score, "v3": meta.CVSSv3.Score, "link": meta.Link,
		}).Debug("DEBUG")
	}

	// Store in bbolt using gob
	data := StoredNVDData{
		Description:      meta.Description,
		Severity:         meta.Severity,
		CVSSv2:           meta.CVSSv2,
		CVSSv3:           meta.CVSSv3,
		PublishedDate:    meta.PublishedDate,
		LastModifiedDate: meta.LastModifiedDate,
		Link:             meta.Link,
		VulnVersions:     meta.VulnVersions,
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(&data); err != nil {
		return fmt.Errorf("gob encode failed: %w", err)
	}

	// Use batch writer for better performance
	return fetcher.batchWriter.add(cve.Cve.ID, buf.Bytes())
}

func (fetcher *NVDMetadataFetcher) toSeverity(s string) common.Priority {
	switch s {
	case "LOW":
		return common.Low
	case "MEDIUM":
		return common.Medium
	case "HIGH":
		return common.High
	case "CRITICAL":
		return common.Critical
	}

	// return empty instead of Unknown
	return ""
}

func (fetcher *NVDMetadataFetcher) GetMetadata(cve string) (*common.NVDMetadata, bool) {
	var stored StoredNVDData

	err := fetcher.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(nvdBucketName))
		data := b.Get([]byte(cve))
		if data == nil {
			return fmt.Errorf("not found")
		}

		dec := gob.NewDecoder(bytes.NewReader(data))
		return dec.Decode(&stored)
	})

	if err != nil {
		return nil, false
	}

	meta := &common.NVDMetadata{
		Description:      stored.Description,
		Severity:         stored.Severity,
		CVSSv2:           stored.CVSSv2,
		CVSSv3:           stored.CVSSv3,
		PublishedDate:    stored.PublishedDate,
		LastModifiedDate: stored.LastModifiedDate,
		Link:             stored.Link,
	}

	// Fallback to web scraping if description empty
	if meta.Description == "" {
		meta.Description = getCveDescription(cve)
	}

	return meta, true
}

// Return affected version and fixed version
func (fetcher *NVDMetadataFetcher) GetAffectedVersion(name string) ([]string, []string, bool) {
	var stored StoredNVDData

	err := fetcher.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(nvdBucketName))
		data := b.Get([]byte(name))
		if data == nil {
			return fmt.Errorf("not found")
		}

		dec := gob.NewDecoder(bytes.NewReader(data))
		return dec.Decode(&stored)
	})

	if err != nil {
		return nil, nil, false
	}

	affects := make([]string, 0)
	fixes := make([]string, 0)
	opAffect := ""
	opFix := ""

	for _, v := range stored.VulnVersions {
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

	return affects, fixes, len(stored.VulnVersions) > 0
}

func (fetcher *NVDMetadataFetcher) Unload() {
	// Clear batch writer
	fetcher.batchWriter = nil

	if fetcher.db != nil {
		fetcher.db.Close()
		fetcher.db = nil
	}

	if fetcher.dbPath != "" {
		os.Remove(fetcher.dbPath)
		log.WithField("path", fetcher.dbPath).Info("Cleaned up NVD bbolt database")
		fetcher.dbPath = ""
	}
}

func (fetcher *NVDMetadataFetcher) Clean() {
	// No-op: cleanup is handled by Unload()
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
