package rocky

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/vul-dbgen/common"
	"github.com/vul-dbgen/updater"

	log "github.com/sirupsen/logrus"
)

var endpoint = "https://apollo.build.resf.org/api/v3/advisories/"

type RockyFetcher struct{}

type apiResponse struct {
	Advisories []advisory `json:"advisories"`
}

type advisory struct {
	Id                  int          `json:"id"`
	Created_at          string       `json:"created_at"`
	Updated_at          string       `json:"updated_at"`
	Published_at        string       `json:"published_at"`
	Name                string       `json:"name"`
	Synopsis            string       `json:"synopsis"`
	Description         string       `json:"description"`
	Kind                string       `json:"kind"`
	Severity            string       `json:"severity"`
	Topic               string       `json:"topic"`
	Red_hat_advisory_id int          `json:"red_hat_advisory_id"`
	AffectedProducts    []Product    `json:"affected_products"`
	Cves                []cve        `json:"cves"`
	Packages            []ApiPackage `json:"packages"`
	Fixes               []Fix        `json:"fixes"`
}

type cve struct {
	Id         int    `json:"id"`
	Cve        string `json:"cve"`
	CvssVector string `json:"cvss3_scoring_vector"`
	CvssScore  string `json:"cvss3_base_score"`
	Cwe        string `json:"cwe"`
}

type ApiPackage struct {
	Id            int    `json"id"`
	Nevra         string `json:"nevra"`
	Checksum      string `json:"checksum"`
	ChecksumType  string `json:"checksum_type"`
	ModuleContext string `json:"module_context"`
	ModuleName    string `json:"module_name"`
	ModuleStream  string `json:"module_stream"`
	ModuleVersion string `json:"module_version"`
	RepoName      string `json:"repo_name"`
	PackageName   string `json:"package_name"`
	ProductName   string `json:"product_name"`
}

type Fix struct {
	Id          int    `json:"id"`
	TicketId    string `json:"ticket_id"`
	Source      string `json:"source"`
	Description string `json:"description"`
}

type Product struct {
	Id           int    `json:"id"`
	Variant      string `json:"variant"`
	Name         string `json:"name"`
	MajorVersion int    `json:"major_version"`
	MinorVersion int    `json:"minor_version"`
	Arch         string `json:"arch"`
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
	resp.Vulnerabilities = parseRockyJSON(remoteResponse)

	log.WithFields(log.Fields{"Vulnerabilities": len(resp.Vulnerabilities)}).Info("fetching rocky done")
	return resp, nil
}

// fetchRemote retrieves and stores the api json response.
func (f *RockyFetcher) fetchRemote() (*apiResponse, error) {
	req, err := http.NewRequest("GET", endpoint, nil)
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
	log.WithFields(log.Fields{"number of advisories": len(jsonResponse.Advisories)}).Debug("Rocky reponse")

	return &jsonResponse, nil
}

// pruneDuplicates returns a slice with all duplicate entries removed from the input slice.
func pruneDuplicates(slice []common.FeatureVersion) []common.FeatureVersion {
	prunedList := []common.FeatureVersion{}
	set := map[string]common.FeatureVersion{}
	for _, entry := range slice {
		if _, ok := set[entry.Feature.Name+":"+entry.Version.String()]; !ok {
			set[entry.Feature.Name+":"+entry.Version.String()] = entry
		}
	}

	for _, val := range set {
		prunedList = append(prunedList, val)
	}

	return prunedList
}

func makeFV(fixPackage ApiPackage, majorVersion int) common.FeatureVersion {
	//Split the nevra for the version
	start := strings.Index(fixPackage.Nevra, ":")
	last := strings.LastIndex(fixPackage.Nevra, ".")
	last = strings.LastIndex(fixPackage.Nevra[:last], ".")
	verString := fixPackage.Nevra[start-1 : last]
	version, err := common.NewVersion(verString)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("Error making rocky linux feature version")
	}

	fixed := common.FeatureVersion{
		Feature: common.Feature{
			Name:      fixPackage.PackageName,
			Namespace: "rocky:" + strconv.Itoa(majorVersion),
		},
		Version: version,
	}
	return fixed
}

// parseRockyJSON takes the data and formats it into the format []common.Vulnerability.
func parseRockyJSON(data *apiResponse) []common.Vulnerability {
	var vulns []common.Vulnerability
	vulMap := map[string]common.Vulnerability{}

	//Iterate over advisory and make the corresponding vulnerability.
	for _, advisory := range data.Advisories {
		Namespaces := getNamespaces(advisory.AffectedProducts)
		vuln := common.Vulnerability{
			Name:        advisory.Name,
			Description: advisory.Description,
			Severity:    translateSeverity(advisory.Severity),
		}
		fixedIns := []common.FeatureVersion{}
		for _, fix := range advisory.Packages {
			fv := makeFV(fix, advisory.AffectedProducts[0].MajorVersion)
			fixedIns = append(fixedIns, fv)
		}
		fixedIns = pruneDuplicates(fixedIns)
		vuln.FixedIn = fixedIns

		//Add entry for each unique namespace
		for _, ns := range Namespaces {
			//Check if the advisory already exists in the namespace
			vuln.Namespace = ns
			if _, ok := vulMap[ns+":"+advisory.Name]; !ok {
				vulMap[ns+":"+advisory.Name] = vuln
			} else {
				log.WithFields(log.Fields{"Name": advisory.Name}).Debug("Duplicate rocky advisory entry")
				continue
			}
		}

	}

	//Make slice from map
	for _, val := range vulMap {
		vulns = append(vulns, val)
	}

	return vulns
}

func getNamespaces(affectedProducts []Product) []string {
	nsMap := map[string]string{}
	for _, product := range affectedProducts {
		majorVersion := strconv.Itoa(product.MajorVersion)
		if _, ok := nsMap["rocky:"+majorVersion]; !ok {
			nsMap["rocky:"+majorVersion] = "rocky:" + majorVersion
		}
	}
	results := []string{}
	for _, val := range nsMap {
		results = append(results, val)
	}
	return results
}

func translateSeverity(incSev string) common.Priority {
	var severity common.Priority
	switch strings.ToLower(incSev) {
	case "important":
		severity = common.High
	case "moderate":
		severity = common.Medium
	case "low":
		severity = common.Low
	case "none":
		severity = common.Low
	default:
		log.WithFields(log.Fields{"sev": incSev}).Debug("unhandled severity")
	}
	return severity
}

func (f *RockyFetcher) Clean() {}
