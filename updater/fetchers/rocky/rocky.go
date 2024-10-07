package rocky

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vul-dbgen/common"
	"github.com/vul-dbgen/updater"

	log "github.com/sirupsen/logrus"
)

var endpoint = "https://errata.rockylinux.org/api/v2/advisories?filters.product=&filters.fetchRelated=true&"
var limit = int64(100)

type RockyFetcher struct{}

type apiResponse struct {
	Advisories []advisory `json:"advisories"`
	Total      int64      `json:"total"`
}

type advisory struct {
	AffectedProducts []string                       `json:"affectedProducts"`
	Cves             []cve                          `json:"cves"`
	Description      string                         `json:"description"`
	Fixes            []fix                          `json:"fixes"`
	Name             string                         `json:"name"`
	PublishedAt      string                         `json:"publishedAt"`
	RPMs             map[string]map[string][]string `json:"rpms"`
	Severity         string                         `json:"severity"`
}

type fix struct {
	Description string `json:"description"`
	SourceBy    string `json:"sourceBy"`
	SourceLink  string `json:"sourceLink"`
	Ticket      string `json:"ticket"`
}

// cve cvss score are currently unfilled by API
type cve struct {
	CvssVector string `json:"cvss3ScoringVector"`
	Cvss3Score string `json:"cvss3BaseScore"`
	Cwe        string `json:"cwe"`
	Name       string `json:"name"`
	SourceBy   string `json:"sourceBy"`
	SourceLink string `json:"sourceLink"`
}

func init() {
	updater.RegisterFetcher("rocky", &RockyFetcher{})
}

func (f *RockyFetcher) FetchUpdate() (resp updater.FetcherResponse, err error) {
	log.WithField("package", "Rocky").Info("Start fetching vulnerabilities")
	//get data from remote
	remoteResponse, err := f.fetchRemote()
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("Error fetching rocky remote")
	}
	//process data into standard format
	resp.Vulnerabilities = translateRockyJSON(remoteResponse)
	log.WithFields(log.Fields{"Vulnerabilities": len(resp.Vulnerabilities)}).Info("fetching rocky done")
	return resp, nil
}

// fetchRemote retrieves and stores the api json response.
func (f *RockyFetcher) fetchRemote() (*apiResponse, error) {
	response, err := fetchRockyLinuxErrata()
	if err != nil {
		return nil, err
	}

	return response, nil
}

// translateRockyJSON translates the apiResponse struct to an array of common.Vulnerability to be used in fetcher response later.
func translateRockyJSON(response *apiResponse) []common.Vulnerability {
	vulns := []common.Vulnerability{}

	for _, advisory := range response.Advisories {
		fixedIns := map[string][]common.FeatureVersion{}
		for key, rpms := range advisory.RPMs {
			nvras := rpms["nvras"]
			namespace := productToNamespace(key)
			fixedIns[namespace] = nvraToFeatureVersion(nvras, namespace)
		}
		entry := common.Vulnerability{
			Name:        advisory.Name,
			Description: advisory.Description,
			Link:        "",
			Severity:    translateSeverity(advisory.Severity),
			IssuedDate:  issuedDate(advisory.PublishedAt),
			CVEs:        []common.CVE{},
		}
		//populate CVEs
		for _, cve := range advisory.Cves {
			commonCVE := common.CVE{
				Name: cve.Name,
			}
			entry.CVEs = append(entry.CVEs, commonCVE)
		}
		//For each potential affected product we need to consider namespace changing
		for _, productName := range advisory.AffectedProducts {
			entry.Namespace = productToNamespace(productName)
			if fi, ok := fixedIns[entry.Namespace]; ok {
				entry.FixedIn = fi
			}
			vulns = append(vulns, entry)
		}
	}
	return vulns
}

func productToNamespace(product string) string {
	lastSpace := strings.LastIndex(product, " ")
	majorVersion := strings.Trim(product[lastSpace:], " ")
	return "rocky:" + majorVersion
}

func issuedDate(dateString string) time.Time {
	defTime := strings.Split(dateString, "T")[0]
	if t, err := time.Parse("2006-01-02", defTime); err == nil {
		return t
	} else {
		return time.Time{}
	}
}

func nvraToFeatureVersion(nvras []string, namespace string) []common.FeatureVersion {
	results := []common.FeatureVersion{}
	//map with key modulename:moduleversion to prevent duplicates
	set := map[string]struct{}{}

	for _, nvraString := range nvras {
		//Remove rpm and arch sections
		lastPeriod := strings.LastIndex(nvraString, ".")
		nvraString = nvraString[:lastPeriod]
		lastPeriod = strings.LastIndex(nvraString, ".")
		nvraString = nvraString[:lastPeriod]
		//Get module name from section before epoch
		epochIndex := strings.Index(nvraString, ":")
		moduleName := nvraString[:epochIndex-2]
		//Remaining section is version
		moduleVersion := nvraString[epochIndex-1:]
		key := moduleName + ":" + moduleVersion
		if _, ok := set[key]; ok {
			continue
		} else {
			set[key] = struct{}{}
		}

		fvVer, err := common.NewVersion(moduleVersion)
		if err != nil {
			log.WithFields(log.Fields{"err": err, "nvra": nvraString, "ftVer": fvVer}).Debug("Error converting nvra to FeatureVersion")
		}
		entry := common.FeatureVersion{
			Feature: common.Feature{
				Name:      moduleName,
				Namespace: namespace,
			},
			Version: fvVer,
		}
		results = append(results, entry)
	}

	return results
}

func fetchRockyLinuxErrata() (*apiResponse, error) {
	results := &apiResponse{}
	page := 0
	count := int64(0)
	total := int64(1)
	count2 := 0
	for count < total {
		req, err := http.NewRequest("GET", endpoint+"page="+strconv.Itoa(page)+"&limit="+strconv.FormatInt(limit, 10), nil)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Error("Error creating rocky linux request")
			return nil, err
		}
		client := http.Client{}
		r, err := client.Do(req)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Error("Error retrieving rocky linux response")
			return nil, err
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Error("Error reading rocky linux response")
			return nil, err
		}
		var jsonResponse apiResponse
		err = json.Unmarshal(body, &jsonResponse)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Error("Error unmarshalling rocky linux response")
		}
		results.Advisories = append(results.Advisories, jsonResponse.Advisories...)
		total = jsonResponse.Total
		count += limit
		page++
		for _, adv := range jsonResponse.Advisories {
			if len(adv.Cves) > 0 || len(adv.Fixes) > 0 {
				count2++
			}
		}
	}
	log.WithFields(log.Fields{"number of advisories": len(results.Advisories)}).Debug("Rocky reponse")
	return results, nil
}

func translateSeverity(incSev string) common.Priority {
	var severity common.Priority
	switch incSev {
	case "SEVERITY_CRITICAL":
		severity = common.Critical
	case "SEVERITY_IMPORTANT":
		severity = common.High
	case "SEVERITY_MODERATE":
		severity = common.Medium
	case "SEVERITY_LOW":
		severity = common.Low
	case "SEVERITY_UNKNOWN":
		severity = common.Low
	default:
		log.WithFields(log.Fields{"sev": incSev}).Debug("unhandled severity")
	}
	return severity
}

func (f *RockyFetcher) Clean() {}
