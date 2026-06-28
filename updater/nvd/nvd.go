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
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	_ "modernc.org/sqlite"

	"github.com/vul-dbgen/common"
)

const (
	jsonUrl      = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%s.json.gz"
	cveURLPrefix = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="

	nvdAPIkey       = "NVD_KEY"
	nvdSubfolder    = "nvd"
	nvdDBName       = "nvd_metadata.db"
	retryTimes      = 5
	timeFormat      = "2006-01-02T15:04Z"
	timeFormatNew   = "2006-01-02T15:04:05"
	resultsPerPage  = 2000
	batchCommitSize = 10000
)

type NVDMetadataFetcher struct {
	nvdkey *string

	// SQLite state
	dbPath string
	db     *sql.DB

	// Prepared statements
	stmtInsertMeta    *sql.Stmt
	stmtInsertVersion *sql.Stmt
	stmtGetMeta       *sql.Stmt
	stmtGetVersions   *sql.Stmt

	// Transaction batching
	txBatch    *sql.Tx
	batchCount int
	batchSize  int
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
	// Determine tmpPath from environment or use system temp
	tmpDir := os.Getenv("NVD_TMP_PATH")
	if tmpDir == "" {
		tmpDir = os.TempDir()
	}

	fetcher.dbPath = filepath.Join(tmpDir, nvdDBName)
	fetcher.batchSize = batchCommitSize

	// Remove stale database
	os.Remove(fetcher.dbPath)
	os.Remove(fetcher.dbPath + "-wal")
	os.Remove(fetcher.dbPath + "-shm")

	// Open with optimized DSN
	dsn := fmt.Sprintf("file:%s?cache=shared&mode=rwc", fetcher.dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("failed to open SQLite: %w", err)
	}

	// Performance tuning pragmas
	pragmas := []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA cache_size = -64000",
		"PRAGMA temp_store = MEMORY",
		"PRAGMA mmap_size = 268435456",
	}

	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return fmt.Errorf("pragma failed: %w", err)
		}
	}

	fetcher.db = db
	return fetcher.createSchema()
}

func (fetcher *NVDMetadataFetcher) createSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS nvd_metadata (
		cve_id TEXT PRIMARY KEY NOT NULL,
		description TEXT NOT NULL DEFAULT '',
		severity TEXT NOT NULL DEFAULT '',
		cvss_v2_vectors TEXT NOT NULL DEFAULT '',
		cvss_v2_score REAL NOT NULL DEFAULT 0.0,
		cvss_v3_vectors TEXT NOT NULL DEFAULT '',
		cvss_v3_score REAL NOT NULL DEFAULT 0.0,
		published_date TEXT NOT NULL DEFAULT '',
		last_modified_date TEXT NOT NULL DEFAULT '',
		link TEXT NOT NULL DEFAULT ''
	) STRICT;

	CREATE INDEX IF NOT EXISTS idx_cve_id ON nvd_metadata(cve_id);

	CREATE TABLE IF NOT EXISTS nvd_vuln_versions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		cve_id TEXT NOT NULL,
		start_including TEXT NOT NULL DEFAULT '',
		start_excluding TEXT NOT NULL DEFAULT '',
		end_including TEXT NOT NULL DEFAULT '',
		end_excluding TEXT NOT NULL DEFAULT '',
		FOREIGN KEY (cve_id) REFERENCES nvd_metadata(cve_id) ON DELETE CASCADE
	) STRICT;

	CREATE INDEX IF NOT EXISTS idx_vuln_versions_cve ON nvd_vuln_versions(cve_id);
	`

	_, err := fetcher.db.Exec(schema)
	return err
}

func (fetcher *NVDMetadataFetcher) prepareStatements() error {
	var err error

	// Insert prepared statements
	fetcher.stmtInsertMeta, err = fetcher.db.Prepare(`
		INSERT OR REPLACE INTO nvd_metadata
		(cve_id, description, severity, cvss_v2_vectors, cvss_v2_score,
		 cvss_v3_vectors, cvss_v3_score, published_date, last_modified_date, link)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}

	fetcher.stmtInsertVersion, err = fetcher.db.Prepare(`
		INSERT INTO nvd_vuln_versions
		(cve_id, start_including, start_excluding, end_including, end_excluding)
		VALUES (?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}

	// Query prepared statements
	fetcher.stmtGetMeta, err = fetcher.db.Prepare(`
		SELECT description, severity, cvss_v2_vectors, cvss_v2_score,
		       cvss_v3_vectors, cvss_v3_score, published_date, last_modified_date, link
		FROM nvd_metadata WHERE cve_id = ?
	`)
	if err != nil {
		return err
	}

	fetcher.stmtGetVersions, err = fetcher.db.Prepare(`
		SELECT start_including, start_excluding, end_including, end_excluding
		FROM nvd_vuln_versions WHERE cve_id = ?
		ORDER BY id
	`)

	return err
}

func (fetcher *NVDMetadataFetcher) beginBatch() error {
	tx, err := fetcher.db.Begin()
	if err != nil {
		return err
	}
	fetcher.txBatch = tx
	fetcher.batchCount = 0
	return nil
}

func (fetcher *NVDMetadataFetcher) commitBatch() error {
	if fetcher.txBatch == nil {
		return nil
	}

	if err := fetcher.txBatch.Commit(); err != nil {
		return err
	}

	log.WithFields(log.Fields{"count": fetcher.batchCount}).Debug("Committed NVD batch")
	fetcher.txBatch = nil
	fetcher.batchCount = 0
	return nil
}

func (fetcher *NVDMetadataFetcher) checkBatchCommit() error {
	fetcher.batchCount++

	if fetcher.batchCount >= fetcher.batchSize {
		if err := fetcher.commitBatch(); err != nil {
			return err
		}
		return fetcher.beginBatch()
	}
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
	// Initialize SQLite database
	if err := fetcher.initDB(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to initialize NVD database")
		return common.ErrCouldNotDownload
	}

	// Prepare statements
	if err := fetcher.prepareStatements(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to prepare NVD statements")
		return common.ErrCouldNotDownload
	}

	// Start initial transaction
	if err := fetcher.beginBatch(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to begin NVD batch")
		return common.ErrCouldNotDownload
	}

	// Load data from files or remote API
	var err error
	nvdFolder := filepath.Join(common.CVESourceRoot, nvdSubfolder)
	if hasPreDownloadFiles(nvdFolder) || hasMergedPreDownloadFiles() {
		_, err = fetcher.loadPreDownload(nvdFolder)
	} else {
		_, err = fetcher.loadRemote()
	}

	// Commit final batch
	commitErr := fetcher.commitBatch()

	if err != nil || commitErr != nil {
		log.WithFields(log.Fields{"loadErr": err, "commitErr": commitErr}).Error("NVD load failed")
		return common.ErrCouldNotDownload
	}

	return nil
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

	files, err := ioutil.ReadDir(folder)
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

	// SQLite insertion logic
	// Use transaction context
	stmt := fetcher.stmtInsertMeta
	if fetcher.txBatch != nil {
		stmt = fetcher.txBatch.Stmt(stmt)
	}

	// Insert metadata row
	_, err := stmt.Exec(
		cve.Cve.ID,
		meta.Description,
		string(meta.Severity),
		meta.CVSSv2.Vectors,
		meta.CVSSv2.Score,
		meta.CVSSv3.Vectors,
		meta.CVSSv3.Score,
		meta.PublishedDate.Format(time.RFC3339),
		meta.LastModifiedDate.Format(time.RFC3339),
		meta.Link,
	)
	if err != nil {
		log.WithFields(log.Fields{"cve": cve.Cve.ID, "error": err}).Error("Failed to insert NVD metadata")
		return err
	}

	// Insert version constraints
	stmtVer := fetcher.stmtInsertVersion
	if fetcher.txBatch != nil {
		stmtVer = fetcher.txBatch.Stmt(stmtVer)
	}

	for _, v := range meta.VulnVersions {
		_, err := stmtVer.Exec(
			cve.Cve.ID,
			v.StartIncluding,
			v.StartExcluding,
			v.EndIncluding,
			v.EndExcluding,
		)
		if err != nil {
			log.WithFields(log.Fields{"cve": cve.Cve.ID, "error": err}).Error("Failed to insert NVD version")
			return err
		}
	}

	// Check if batch should commit
	return fetcher.checkBatchCommit()
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
	var meta common.NVDMetadata
	var severityStr, publishedStr, modifiedStr string

	err := fetcher.stmtGetMeta.QueryRow(cve).Scan(
		&meta.Description,
		&severityStr,
		&meta.CVSSv2.Vectors,
		&meta.CVSSv2.Score,
		&meta.CVSSv3.Vectors,
		&meta.CVSSv3.Score,
		&publishedStr,
		&modifiedStr,
		&meta.Link,
	)

	if err == sql.ErrNoRows {
		return nil, false
	}
	if err != nil {
		log.WithFields(log.Fields{"cve": cve, "error": err}).Error("Failed to query NVD metadata")
		return nil, false
	}

	// Parse severity
	meta.Severity = common.Priority(severityStr)

	// Parse timestamps
	if publishedStr != "" {
		if t, err := time.Parse(time.RFC3339, publishedStr); err == nil {
			meta.PublishedDate = t
		}
	}
	if modifiedStr != "" {
		if t, err := time.Parse(time.RFC3339, modifiedStr); err == nil {
			meta.LastModifiedDate = t
		}
	}

	// Fallback to web scraping if description empty
	if meta.Description == "" {
		meta.Description = getCveDescription(cve)
	}

	return &meta, true
}

// Return affected version and fixed version
func (fetcher *NVDMetadataFetcher) GetAffectedVersion(name string) ([]string, []string, bool) {
	rows, err := fetcher.stmtGetVersions.Query(name)
	if err != nil {
		log.WithFields(log.Fields{"cve": name, "error": err}).Error("Failed to query NVD versions")
		return nil, nil, false
	}
	defer rows.Close()

	affects := make([]string, 0)
	fixes := make([]string, 0)
	opAffect := ""
	opFix := ""
	found := false

	for rows.Next() {
		found = true
		var v common.NVDvulnerableVersion

		if err := rows.Scan(&v.StartIncluding, &v.StartExcluding, &v.EndIncluding, &v.EndExcluding); err != nil {
			log.WithFields(log.Fields{"cve": name, "error": err}).Error("Failed to scan NVD version")
			continue
		}

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

	if err := rows.Err(); err != nil {
		log.WithFields(log.Fields{"cve": name, "error": err}).Error("NVD row iteration error")
	}

	return affects, fixes, found
}

func (fetcher *NVDMetadataFetcher) Unload() {
	// Close prepared statements
	if fetcher.stmtInsertMeta != nil {
		fetcher.stmtInsertMeta.Close()
		fetcher.stmtInsertMeta = nil
	}
	if fetcher.stmtInsertVersion != nil {
		fetcher.stmtInsertVersion.Close()
		fetcher.stmtInsertVersion = nil
	}
	if fetcher.stmtGetMeta != nil {
		fetcher.stmtGetMeta.Close()
		fetcher.stmtGetMeta = nil
	}
	if fetcher.stmtGetVersions != nil {
		fetcher.stmtGetVersions.Close()
		fetcher.stmtGetVersions = nil
	}

	// Close database connection
	if fetcher.db != nil {
		if err := fetcher.db.Close(); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to close NVD database")
		}
		fetcher.db = nil
	}

	// Delete temporary database files
	if fetcher.dbPath != "" {
		if err := os.Remove(fetcher.dbPath); err != nil && !os.IsNotExist(err) {
			log.WithFields(log.Fields{"path": fetcher.dbPath, "error": err}).Warn("Failed to remove NVD database")
		}
		// Remove WAL files
		os.Remove(fetcher.dbPath + "-wal")
		os.Remove(fetcher.dbPath + "-shm")

		log.WithFields(log.Fields{"path": fetcher.dbPath}).Info("Cleaned up NVD database")
		fetcher.dbPath = ""
	}
}

func (fetcher *NVDMetadataFetcher) Clean() {
	// No-op: SQLite cleanup is handled by Unload()
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
