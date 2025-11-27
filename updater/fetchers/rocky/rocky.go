package rocky

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/vul-dbgen/common"
	"github.com/vul-dbgen/updater"

	log "github.com/sirupsen/logrus"
)

const (
	baseURL  = "https://apollo.build.resf.org/api/v3/advisories/"
	pageSize = 100
)

type RockyFetcher struct{}

type apiResponse struct {
	Advisories    []advisory `json:"advisories"`
	Total         int64      `json:"total"`
	Page          int        `json:"page"`
	Size          int        `json:"size"`
	LastUpdatedAt string     `json:"last_updated_at"`
}

type advisory struct {
	ID               int               `json:"id"`
	Name             string            `json:"name"`
	Synopsis         string            `json:"synopsis"`
	Description      string            `json:"description"`
	Kind             string            `json:"kind"`
	Severity         string            `json:"severity"`
	Topic            string            `json:"topic"`
	PublishedAt      string            `json:"published_at"`
	CreatedAt        string            `json:"created_at"`
	UpdatedAt        string            `json:"updated_at"`
	RedHatAdvisoryID int               `json:"red_hat_advisory_id"`
	AffectedProducts []affectedProduct `json:"affected_products"`
	Cves             []cve             `json:"cves"`
	Fixes            []fix             `json:"fixes"`
	Packages         []pkg             `json:"packages"`
}

type affectedProduct struct {
	ID           int    `json:"id"`
	Variant      string `json:"variant"`
	Name         string `json:"name"`
	MajorVersion int    `json:"major_version"`
	MinorVersion int    `json:"minor_version"`
	Arch         string `json:"arch"`
}

type cve struct {
	ID                 int    `json:"id"`
	Cve                string `json:"cve"`
	Cvss3ScoringVector string `json:"cvss3_scoring_vector"`
	Cvss3BaseScore     string `json:"cvss3_base_score"`
	Cwe                string `json:"cwe"`
}

type fix struct {
	ID          int    `json:"id"`
	TicketID    string `json:"ticket_id"`
	Source      string `json:"source"`
	Description string `json:"description"`
}

type pkg struct {
	ID            int     `json:"id"`
	Nevra         string  `json:"nevra"`
	Checksum      string  `json:"checksum"`
	ChecksumType  string  `json:"checksum_type"`
	ModuleContext *string `json:"module_context"`
	ModuleName    *string `json:"module_name"`
	ModuleStream  *string `json:"module_stream"`
	ModuleVersion *string `json:"module_version"`
	RepoName      string  `json:"repo_name"`
	PackageName   string  `json:"package_name"`
	ProductName   string  `json:"product_name"`
}

func init() {
	updater.RegisterFetcher("rocky", &RockyFetcher{})
}

func (f *RockyFetcher) FetchUpdate() (resp updater.FetcherResponse, err error) {
	log.WithField("package", "Rocky").Info("Start fetching vulnerabilities")
	//get data from remote
	remoteResponse, err := f.fetchRemote()
	if err != nil || remoteResponse == nil {
		log.WithFields(log.Fields{"err": err}).Error("Error fetching rocky remote")
		return resp, err
	}
	//process data into standard format
	resp.Vulnerabilities = translateRockyJSON(remoteResponse)
	log.WithFields(log.Fields{"Vulnerabilities": len(resp.Vulnerabilities)}).Info("fetching rocky done")
	return resp, nil
}

// fetchRemote retrieves and stores the api json response.
func (f *RockyFetcher) fetchRemote() (*apiResponse, error) {
	response, err := fetchRockyLinuxErrata(context.Background())
	if err != nil {
		return nil, err
	}

	return response, nil
}

// productNameToNamespace extracts major version from product name string
// Example: "Rocky Linux 10 x86_64" -> "rocky:10"
func productNameToNamespace(productName string) string {
	fields := strings.Fields(productName)
	for _, f := range fields {
		if v, err := strconv.ParseFloat(f, 64); err == nil {
			// Only convert to the floor value of the float, e.g. 9.6 -> 9
			return fmt.Sprintf("rocky:%d", int(v))
		}
	}
	return fmt.Sprintf("rocky:%s", productName)
}

// extractVersionFromNevra parses a NEVRA-formatted RPM string to extract the version.
//
// NEVRA format: name-[epoch:]version-release.arch.rpm
// Example with epoch:
//
//	"valkey-0:8.0.6-2.el10_1.ppc64le.rpm" -> "8.0.6-2.el10_1"
func extractVersionFromNevra(nvraString string) string {
	lastPeriod := strings.LastIndex(nvraString, ".")
	nvraString = nvraString[:lastPeriod]
	lastPeriod = strings.LastIndex(nvraString, ".")
	nvraString = nvraString[:lastPeriod]
	//Get module name from section before epoch
	epochIndex := strings.Index(nvraString, ":")

	//Remaining section is version
	moduleVersion := nvraString[epochIndex-1:]
	return moduleVersion
}

// buildFixedInByNamespace organizes fixed package versions by Rocky Linux product namespace.
//
// It groups the provided packages by Rocky major version (namespace) derived from ProductName,
// ignoring package architecture.
//
// Example:
//
//	input: affectedProducts: [{ProductName: "Rocky Linux 9.4"}, {ProductName: "Rocky Linux 9.5"}]
//	       packages: [{ProductName: "Rocky Linux 9.4", PackageName: "...", Nevra: ...}, ...]
//	output: {
//	    "rocky:9": [FeatureVersion{...}, ...]
//	}
func buildFixedInByNamespace(affectedProducts []affectedProduct, packages []pkg) (map[string][]common.FeatureVersion, error) {
	// The map works in the following way:
	// rocky:9.4 => [8.0.6-2.el10_1] => common.FeatureVersion(8.0.6-2.el10_1)
	packagesByNamespace := make(map[string]map[string]common.FeatureVersion)
	for _, affectedProduct := range affectedProducts {
		packagesByNamespace[fmt.Sprintf("rocky:%d", affectedProduct.MajorVersion)] = make(map[string]common.FeatureVersion)
	}

	for _, pkg := range packages {
		affectedProductNamespace := productNameToNamespace(pkg.ProductName)
		groupPakcage, ok := packagesByNamespace[affectedProductNamespace]
		if !ok {
			packagesByNamespace[affectedProductNamespace] = make(map[string]common.FeatureVersion)
			groupPakcage = packagesByNamespace[affectedProductNamespace]
		}

		pkgVersion := extractVersionFromNevra(pkg.Nevra)
		if _, existing := groupPakcage[pkgVersion]; !existing {
			fvVer, err := common.NewVersion(pkgVersion)
			if err != nil {
				log.WithFields(log.Fields{"err": err, "version": pkgVersion, "ftVer": fvVer}).Debug("Error converting version to FeatureVersion")
			}

			groupPakcage[pkgVersion] = common.FeatureVersion{
				Feature: common.Feature{
					Name:      pkg.PackageName,
					Namespace: affectedProductNamespace,
				},
				Version: fvVer,
			}
		}
	}

	result := make(map[string][]common.FeatureVersion)
	for _, groupPakcage := range packagesByNamespace {
		for _, featureVersion := range groupPakcage {
			result[featureVersion.Feature.Namespace] = append(result[featureVersion.Feature.Namespace], featureVersion)
		}
	}

	return result, nil
}

// translateRockyJSON translates the apiResponse struct to an array of common.Vulnerability to be used in fetcher response later.
func translateRockyJSON(response *apiResponse) []common.Vulnerability {
	vulns := []common.Vulnerability{}
	for _, advisory := range response.Advisories {
		cves := make([]common.CVE, len(advisory.Cves))
		for i, c := range advisory.Cves {
			cves[i] = common.CVE{Name: c.Cve}
		}

		fixedInByNS, err := buildFixedInByNamespace(advisory.AffectedProducts, advisory.Packages)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Error("Error building fixedInByNamespace")
			continue
		}
		for ns, fixedIn := range fixedInByNS {
			vulns = append(vulns, common.Vulnerability{
				Name:        advisory.Name,
				Description: advisory.Description,
				Link:        "",
				Severity:    translateSeverity(advisory.Severity),
				IssuedDate:  issuedDate(advisory.PublishedAt),
				CVEs:        cves,
				Namespace:   ns,
				FixedIn:     fixedIn,
			})
		}
	}
	return vulns
}

func issuedDate(dateString string) time.Time {
	defTime := strings.Split(dateString, "T")[0]
	if t, err := time.Parse("2006-01-02", defTime); err == nil {
		return t
	} else {
		return time.Time{}
	}
}

func translateSeverity(incSev string) common.Priority {
	switch incSev {
	case "Critical":
		return common.Critical
	case "Important":
		return common.High
	case "Moderate":
		return common.Medium
	case "Low", "None", "Unknown":
		return common.Low
	default:
		log.WithFields(log.Fields{"severity": incSev}).Warn("unhandled severity, defaulting to Low")
		return common.Low
	}
}

func (f *RockyFetcher) Clean() {}

func fetchRockyLinuxErrata(ctx context.Context) (*apiResponse, error) {
	client := retryablehttp.NewClient()
	client.RetryMax = 5
	client.Logger = nil

	results := &apiResponse{}
	page := 1

	for {
		url := fmt.Sprintf("%s?page=%d&size=%d", baseURL, page, pageSize)

		req, err := retryablehttp.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetching page %d: %w", page, err)
		}

		var jsonResp apiResponse
		err = json.NewDecoder(resp.Body).Decode(&jsonResp)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("decoding page %d: %w", page, err)
		}
		results.Advisories = append(results.Advisories, jsonResp.Advisories...)

		if int64(len(results.Advisories)) >= jsonResp.Total {
			break
		}
		page++
	}

	return results, nil
}
