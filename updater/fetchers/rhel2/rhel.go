package rhel2

import (
	"bufio"
	"compress/bzip2"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/vul-dbgen/common"
	utils "github.com/vul-dbgen/share"
	"github.com/vul-dbgen/updater"
)

const (
	minCount = 20000

	retryTimes   = 5
	ovalURI2     = "https://www.redhat.com/security/data/oval/v2/"
	repoToCpeUrl = "https://www.redhat.com/security/data/metrics/repository-to-cpe.json"
	pyxisUrl     = "https://catalog.redhat.com/api/containers/v1/images/nvr"

	rhelSubfolder = "redhat"
)

var (
	ignoredCriterions = []string{
		" is signed with Red Hat ",
		" Client is installed",
		" Workstation is installed",
		" ComputeNode is installed",
	}
	rhsaOS = []int{7, 8, 9}

	rhsaRegexp = regexp.MustCompile(`>[0-9a-zA-Z_\-\.]*.oval.xml.bz2<`)
)

type oval struct {
	Definitions []definition `xml:"definitions>definition"`
}

type definition struct {
	Class       string      `xml:"class,attr"`
	Title       string      `xml:"metadata>title"`
	Description string      `xml:"metadata>description"`
	References  []reference `xml:"metadata>reference"`
	Criteria    criteria    `xml:"criteria"`
	Severity    string      `xml:"metadata>advisory>severity"`
	Issued      issued      `xml:"metadata>advisory>issued"`
	LastMod     updated     `xml:"metadata>advisory>updated"`
	Cves        []cve       `xml:"metadata>advisory>cve"`
	CpeList     CpeList     `xml:"metadata>advisory>affected_cpe_list"`
}

type CpeList struct {
	CPEs []string `xml:"cpe"`
}

type reference struct {
	Source string `xml:"source,attr"`
	URI    string `xml:"ref_url,attr"`
	ID     string `xml:"ref_id,attr"`
}

type issued struct {
	Date string `xml:"date,attr"`
}

type updated struct {
	Date string `xml:"date,attr"`
}

type cve struct {
	Cvss2  string `xml:"cvss2,attr"`
	Cvss3  string `xml:"cvss3,attr"`
	Impact string `xml:"impact,attr"`
	Href   string `xml:"href,attr"`
	ID     string `xml:",chardata"`
}

type criteria struct {
	Operator   string      `xml:"operator,attr"`
	Criterias  []*criteria `xml:"criteria"`
	Criterions []criterion `xml:"criterion"`
}

type criterion struct {
	Comment string `xml:"comment,attr"`
	TestRef string `xml:"test_ref,attr"`
}

// RHELFetcher implements updater.Fetcher and gets vulnerability updates from
// the Red Hat OVAL definitions.
type RHELFetcher struct{}

type RHELCpeFetcher struct{}

func init() {
	updater.RegisterFetcher("redhat", &RHELFetcher{})
	updater.RegisterRawFetcher("redhat", &RHELCpeFetcher{})
}

func (f *RHELCpeFetcher) FetchUpdate() (updater.RawFetcherResponse, error) {
	var resp updater.RawFetcherResponse

	log.Info("fetching Red Hat CPE map")

	req, err := http.NewRequest("GET", repoToCpeUrl, nil)
	req.Header.Add("User-Agent", "dbgen")
	client := http.Client{}
	r, err := client.Do(req)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Could not download CPE mapping json")
		return resp, err
	}
	body, _ := ioutil.ReadAll(r.Body)
	r.Body.Close()

	log.WithFields(log.Fields{"size": len(body), "file": common.RHELCpeMapFile}).Info("fetching Red Hat CPE map done")
	return updater.RawFetcherResponse{Name: common.RHELCpeMapFile, Raw: body}, nil
}

func (f *RHELCpeFetcher) Clean() {}

func (f *RHELFetcher) fetchPreDownload(rhelFolder string) ([]common.Vulnerability, error) {
	var results []common.Vulnerability

	for _, ros := range rhsaOS {
		folder := fmt.Sprintf("%s/%d", rhelFolder, ros)
		files, err := ioutil.ReadDir(folder)
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".xml.bz2") {
				log.WithFields(log.Fields{"os": ros, "file": f.Name()}).Debug("Read redhat feed")

				rfp, err := os.Open(fmt.Sprintf("%s/%s", folder, f.Name()))
				cr := bzip2.NewReader(rfp)
				vs, err := parseRHSA(ros, f.Name(), cr)
				rfp.Close()

				if err != nil {
					return nil, err
				}
				for _, v := range vs {
					results = append(results, v)
				}
			}
		}
	}

	return results, nil
}

func (f *RHELFetcher) fetchRemote() ([]common.Vulnerability, error) {
	var results []common.Vulnerability

	for _, ros := range rhsaOS {
		rurl := fmt.Sprintf("%sRHEL%d/", ovalURI2, ros)
		req, err := http.NewRequest("GET", rurl, nil)
		req.Header.Add("User-Agent", "dbgen")
		client := http.Client{}
		r, err := client.Do(req)
		if err != nil {
			log.Errorf("could not download RHEL's directory: %s", err)
			return nil, common.ErrCouldNotDownload
		}

		// Get the list of RHSAs that we have to process.
		var rhsaList []string
		scanner := bufio.NewScanner(r.Body)
		for scanner.Scan() {
			line := scanner.Text()
			r := rhsaRegexp.FindStringSubmatch(line)
			if len(r) == 1 {
				if fn := r[0][1 : len(r[0])-1]; strings.HasPrefix(fn, "rhel-") {
					rhsaList = append(rhsaList, fn)
				}
				if fn := r[0][1 : len(r[0])-1]; strings.HasPrefix(fn, "rhsso-") {
					rhsaList = append(rhsaList, fn)
				}
			}
		}

		r.Body.Close()

		for i, rhsa := range rhsaList {
			var vs []common.Vulnerability
			// Download the RHSA's XML file.
			retry := 0
			for retry <= retryTimes {
				client := http.Client{}
				rurl = fmt.Sprintf("%sRHEL%d/%s", ovalURI2, ros, rhsa)
				req, err := http.NewRequest("GET", rurl, nil)
				req.Header.Add("User-Agent", "dbgen")
				r, err := client.Do(req)
				if err != nil {
					if retry == retryTimes {
						log.Errorf("could not download RHEL's update file: %s", err)
						return nil, common.ErrCouldNotDownload
					}
				} else {
					// Parse the XML.
					br := bufio.NewReader(r.Body)
					cr := bzip2.NewReader(br)
					vs, err = parseRHSA(ros, rhsa, cr)

					r.Body.Close()
					if err != nil && retry == retryTimes {
						log.WithFields(log.Fields{"rhsa": rhsa, "retry": retryTimes}).Error("Failed to parse, skip")
						break
					}
					if err == nil {
						// Collect vulnerabilities.
						for _, v := range vs {
							results = append(results, v)
						}
						break
					}
				}
				time.Sleep(time.Second * 2)
				retry++
			}

			// Pause to prevent the website from blacklisting us.
			if i%20 == 0 {
				time.Sleep(time.Second * 2)
			}
		}
	}

	return results, nil
}

func (f *RHELFetcher) FetchUpdate() (resp updater.FetcherResponse, err error) {
	log.Info("fetching Red Hat vulnerabilities")

	var results []common.Vulnerability

	rhelFolder := fmt.Sprintf("%s/%s", common.CVESourceRoot, rhelSubfolder)
	if _, err = os.Stat(rhelFolder); os.IsNotExist(err) {
		results, err = f.fetchRemote()
	} else {
		results, err = f.fetchPreDownload(rhelFolder)
	}
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		return resp, common.ErrCouldNotDownload
	}

	if len(results) < minCount {
		log.WithFields(log.Fields{"count": len(results), "min": minCount}).Error("Red Hat CVE count too small")
		return resp, fmt.Errorf("Red Hat CVE count too small, %d < %d", len(results), minCount)
	}

	resp.Vulnerabilities = cullAllVulns(results)
	log.WithFields(log.Fields{"Vulnerabilities": len(results)}).Info("fetching Red Hat done")

	return resp, nil
}

func isDuplicateFeatureVersion(obja common.FeatureVersion, objb common.FeatureVersion) bool {
	if obja.Name == objb.Name &&
		obja.Feature.Name == objb.Feature.Name &&
		obja.Feature.Namespace == objb.Feature.Namespace {
		return true
	}
	return false
}

func cullAllVulns(respVuln []common.Vulnerability) []common.Vulnerability {
	allVulns := makeCveMap(respVuln)
	rhsamap, cveMap, rhsas := getRHSACVEs(allVulns)
	cullVulns(rhsamap, cveMap)
	//add the rhsas back to the cves after culling
	for _, val := range rhsas {
		key := fmt.Sprintf("%v:%v", val.Namespace, val.Name)
		cveMap[key] = val
	}

	remainingVulns := make([]common.Vulnerability, 0)
	for _, val := range cveMap {
		remainingVulns = append(remainingVulns, val)
	}
	result := remainingVulns
	return result
}

func makeCveMap(allVulns []common.Vulnerability) map[string]common.Vulnerability {
	cveMap := make(map[string]common.Vulnerability)

	for _, vuln := range allVulns {
		key := fmt.Sprintf("%s:%s", vuln.Namespace, vuln.Name)

		if exist, ok := cveMap[key]; !ok {
			// entry doesn't exist, create it.
			cveMap[key] = vuln
		} else {
			// merge feature version and cpe
			fixes := utils.NewSetFromSliceKind(exist.FixedIn)
			cpes := utils.NewSetFromSliceKind(exist.CPEs)
			for _, f := range vuln.FixedIn {
				if !fixes.Contains(f) {
					exist.FixedIn = append(exist.FixedIn, f)
				}
			}
			for _, c := range vuln.CPEs {
				if !cpes.Contains(c) {
					exist.CPEs = append(exist.CPEs, c)
				}
			}
			cveMap[key] = exist
		}

	}

	return cveMap
}

//getRHSACVEs returns a map of all CVE names to the matching RHSA entries.
func getRHSACVEs(fullVulns map[string]common.Vulnerability) (map[string][]common.Vulnerability, map[string]common.Vulnerability, map[string]common.Vulnerability) {
	result := make(map[string][]common.Vulnerability)
	cves := make(map[string]common.Vulnerability)
	rhsas := make(map[string]common.Vulnerability)

	for _, vuln := range fullVulns {
		if strings.Contains(strings.ToLower(vuln.Name), "rhsa") {
			rhsaskey := fmt.Sprintf("%s:%s", vuln.Namespace, vuln.Name)
			rhsas[rhsaskey] = vuln
			for _, cve := range vuln.CVEs {
				key := fmt.Sprintf("%s:%s", vuln.Namespace, cve.Name)
				//if slice doesn't exist
				if _, ok := result[key]; !ok {
					//if the data exists, initialize the slice
					if _, ok := fullVulns[key]; ok {
						result[key] = []common.Vulnerability{vuln}
					}
					continue
				}
				//slice exists, append to slice.
				if _, ok := fullVulns[key]; ok {
					result[key] = append(result[key], vuln)
				}
			}
		} else {
			//cve case
			key := fmt.Sprintf("%s:%s", vuln.Namespace, vuln.Name)
			if _, ok := cves[key]; !ok {
				//entry doesn't exist, create it.
				cves[key] = vuln
			}
		}
	}
	return result, cves, rhsas
}

func cullVulns(rhsamap map[string][]common.Vulnerability, cvemap map[string]common.Vulnerability) {
	for cvekey, vuln := range cvemap {
		key := fmt.Sprintf("%s:%s", vuln.Namespace, vuln.Name)
		remainingFeatures := vuln.FixedIn
		if rhsas, ok := rhsamap[key]; ok {
			for _, rhsa := range rhsas {
				//Remove any features covered by an associated RHSA.
				remainingFeatures = removeMatchingFeatures(remainingFeatures, rhsa.FixedIn)
				if len(remainingFeatures) == 0 {
					//remove the cve since there are no remaining features that could be vulnerable.
					delete(cvemap, key)
					break
				} else {
					vuln.FixedIn = remainingFeatures
					cvemap[cvekey] = vuln
				}
			}
		}
	}
}

//removeMatchingFeatures removes entries in entryA that match an entry in entryB
func removeMatchingFeatures(entryA []common.FeatureVersion, entryB []common.FeatureVersion) []common.FeatureVersion {
	result := make([]common.FeatureVersion, 0)
	foundFeatures := make(map[string]bool)
	for _, entry := range entryB {
		foundFeatures[entry.Feature.Name] = true
	}
	for _, entry := range entryA {
		if _, ok := foundFeatures[entry.Feature.Name]; !ok {
			result = append(result, entry)
		}
	}

	return result
}

func parseRHSA(ros int, rhsa string, ovalReader io.Reader) (vulnerabilities []common.Vulnerability, err error) {
	// Decode the XML.
	var ov oval
	err = xml.NewDecoder(ovalReader).Decode(&ov)
	if err != nil {
		log.WithFields(log.Fields{"rhsa": rhsa, "error": err}).Error("Could not decode RHEL's XML")
		log.Errorf("could not decode RHEL's XML: %s", err)
		err = common.ErrCouldNotParse
		return
	}

	// Iterate over the definitions and collect any vulnerabilities that affect
	// at least one package.
	for _, definition := range ov.Definitions {
		var nameId string

		if strings.HasPrefix(name(definition), "RHSA-") {
			nameId = name(definition)
			if year, e := common.ParseYear(nameId[5:]); e != nil {
				log.WithFields(log.Fields{"name": nameId}).Warn("Unexpected vulnerability name")
				continue
			} else if year < common.FirstYear {
				continue
			}
		} else if strings.HasPrefix(cveName(definition), "CVE-") {
			nameId = cveName(definition)
			if year, e := common.ParseYear(nameId[4:]); e != nil {
				log.WithFields(log.Fields{"name": nameId}).Warn("Unexpected vulnerability name")
				continue
			} else if year < common.FirstYear {
				continue
			}
		} else {
			if !strings.Contains(definition.Title, "This file intentionally left empty") {
				log.WithFields(log.Fields{"rhsa": rhsa, "Title": definition.Title}).Warn("Failed to get CVE name")
			}
			continue
		}

		if strings.HasPrefix(description(definition), "Red Hat's versions of the associated software have been determined to NOT be affected") {
			// log.WithFields(log.Fields{"rhsa": rhsa, "name": nameId}).Info("Ignore unaffected vulnerability")
		}

		pkgs := toFeatureVersions(ros, rhsa, nameId, definition.Criteria)
		if len(pkgs) > 0 {
			v := common.Vulnerability{
				Name:        nameId,
				Namespace:   "centos" + ":" + strconv.Itoa(ros),
				Link:        link(definition),
				Severity:    severity(definition),
				Description: description(definition),
				IssuedDate:  issuedDate(definition),
				LastModDate: lastModDate(definition),
				CPEs:        definition.CpeList.CPEs,
				FeedRating:  definition.Severity,
			}
			if v.Link == "" {
				v.Link = cveLink(definition)
			}

			for _, p := range pkgs {
				v.FixedIn = append(v.FixedIn, p)
			}
			for _, r := range definition.Cves {
				var v2, v3 string
				var s2, s3 float64
				if s := strings.Index(r.Cvss2, "/"); s != -1 {
					if score, err := strconv.ParseFloat(r.Cvss2[:s], 64); err == nil {
						s2 = score
						v2 = r.Cvss2[s+1:]
					}
				}
				if s := strings.Index(r.Cvss3, "/"); s != -1 {
					if score, err := strconv.ParseFloat(r.Cvss3[:s], 64); err == nil {
						s3 = score
						v3 = r.Cvss3[s+1:]
					}
				}
				cve := common.CVE{
					Name:   r.ID,
					CVSSv2: common.CVSS{Vectors: v2, Score: s2},
					CVSSv3: common.CVSS{Vectors: v3, Score: s3},
				}
				if s2 > v.CVSSv2.Score {
					v.CVSSv2 = cve.CVSSv2
				}
				if s3 > v.CVSSv3.Score {
					v.CVSSv3 = cve.CVSSv3
				}
				v.CVEs = append(v.CVEs, cve)
			}
			if v.IssuedDate.IsZero() {
				v.IssuedDate = v.LastModDate
			}
			if v.LastModDate.IsZero() {
				v.LastModDate = v.IssuedDate
			}

			common.DEBUG_VULN(&v, "redhat")

			vulnerabilities = append(vulnerabilities, v)
		}
	}

	return
}

func getCriterions(node criteria) [][]criterion {
	// Filter useless criterions.
	var criterions []criterion
	for _, c := range node.Criterions {
		ignored := false

		for _, ignoredItem := range ignoredCriterions {
			if strings.Contains(c.Comment, ignoredItem) {
				ignored = true
				break
			}
		}

		if !ignored {
			criterions = append(criterions, c)
		}
	}

	if node.Operator == "AND" {
		return [][]criterion{criterions}
	} else if node.Operator == "OR" {
		var possibilities [][]criterion
		for _, c := range criterions {
			possibilities = append(possibilities, []criterion{c})
		}
		return possibilities
	}

	return [][]criterion{}
}

func getPossibilities(cvename string, node criteria) [][]criterion {
	if len(node.Criterias) == 0 {
		return getCriterions(node)
	}

	var possibilitiesToCompose [][][]criterion
	for _, criteria := range node.Criterias {
		possibilitiesToCompose = append(possibilitiesToCompose, getPossibilities(cvename, *criteria))
	}
	if len(node.Criterions) > 0 {
		possibilitiesToCompose = append(possibilitiesToCompose, getCriterions(node))
	}

	var possibilities [][]criterion
	if node.Operator == "AND" {
		for _, possibility := range possibilitiesToCompose[0] {
			possibilities = append(possibilities, possibility)
		}

		for _, possibilityGroup := range possibilitiesToCompose[1:] {
			var newPossibilities [][]criterion

			for _, possibility := range possibilities {
				for _, possibilityInGroup := range possibilityGroup {
					var p []criterion
					p = append(p, possibility...)
					p = append(p, possibilityInGroup...)
					newPossibilities = append(newPossibilities, p)
				}
			}

			possibilities = newPossibilities
		}
	} else if node.Operator == "OR" {
		for _, possibilityGroup := range possibilitiesToCompose {
			for _, possibility := range possibilityGroup {
				possibilities = append(possibilities, possibility)
			}
		}
	}

	return possibilities
}

func toFeatureVersions(ros int, rhsa, cvename string, criteria criteria) []common.FeatureVersion {
	// There are duplicates in Red Hat .xml files.
	// This map is for deduplication.
	featureVersionParameters := make(map[string]common.FeatureVersion)

	possibilities := getPossibilities(cvename, criteria)
	for _, criterions := range possibilities {
		var (
			featureVersion common.FeatureVersion
			osVersion      int = ros
			err            error
		)

		// Attempt to parse package data from trees of criterions.
		for _, c := range criterions {
			if strings.Contains(c.Comment, " is installed") && strings.Contains(c.Comment, "Red Hat Enterprise Linux ") {
				/*
					const prefixLen = len("Red Hat Enterprise Linux ")
					a := strings.Index(c.Comment[prefixLen:], " ")
					osVersion, err = strconv.Atoi(strings.TrimSpace(c.Comment[prefixLen : prefixLen+a]))
					if err != nil {
						log.WithFields(log.Fields{"rhsa": rhsa, "cve": cvename, "error": err, "comment": c.Comment}).Warn("Failed to parse release version")
					}
				*/
			} else if strings.Contains(c.Comment, " is earlier than ") {
				const prefixLen = len(" is earlier than ")
				featureVersion.Feature.Name = strings.TrimSpace(c.Comment[:strings.Index(c.Comment, " is earlier than ")])
				verStr := c.Comment[strings.Index(c.Comment, " is earlier than ")+prefixLen:]
				epoch := ""
				if a := strings.Index(verStr, ":"); a > 0 {
					epoch = verStr[:a+1]
					verStr = verStr[a+1:]
				}
				if verStr[:3] == "svn" {
					verStr = verStr[3:]
				}
				if verStr[:1] == "v" {
					verStr = verStr[1:]
				}
				if epoch != "" {
					verStr = epoch + verStr
				}
				featureVersion.Version, err = common.NewVersion(verStr)
				if err != nil {
					log.WithFields(log.Fields{"rhsa": rhsa, "cve": cvename, "error": err, "comment": c.Comment, "version": verStr}).Warn("Failed to parse release version")
				}
			} else if strings.Contains(c.TestRef, ".unaffected:") {
				if a := strings.Index(c.Comment, " is not installed"); a > 0 {
					featureVersion.Feature.Name = strings.TrimSpace(c.Comment[:a])
				} else if a := strings.Index(c.Comment, " is installed"); a > 0 {
					featureVersion.Feature.Name = strings.TrimSpace(c.Comment[:a])
				}
				featureVersion.Version = common.MinVersion
			} else {
				if a := strings.Index(c.Comment, " is installed"); a > 0 {
					featureVersion.Feature.Name = strings.TrimSpace(c.Comment[:a])
				}
				featureVersion.Version = common.MaxVersion
			}
		}

		featureVersion.Feature.Namespace = "centos" + ":" + strconv.Itoa(osVersion)

		if featureVersion.Feature.Namespace != "" && featureVersion.Feature.Name != "" && featureVersion.Version.String() != "" {
			featureVersionParameters[featureVersion.Feature.Namespace+":"+featureVersion.Feature.Name] = featureVersion
		} else {
			//log.WithFields(log.Fields{"Namespace": featureVersion.Feature.Namespace,
			//	"Feature": featureVersion.Feature.Name,
			//	"Version": featureVersion.Version.String(),
			//}).Warn("criterions")
			//log.WithFields(log.Fields{"criteria": criterions}).Warn("Failed to determine a valid package from criterions")
		}
	}

	// Convert the map to slice.
	var featureVersionParametersArray []common.FeatureVersion
	for _, fv := range featureVersionParameters {
		featureVersionParametersArray = append(featureVersionParametersArray, fv)
	}

	return featureVersionParametersArray
}

func description(def definition) (desc string) {
	// It is much more faster to proceed like this than using a Replacer.
	desc = strings.Replace(def.Description, "\n\n\n", " ", -1)
	desc = strings.Replace(desc, "\n\n", " ", -1)
	desc = strings.Replace(desc, "\n", " ", -1)
	return
}

func name(def definition) string {
	if a := strings.Index(def.Title, ": "); a > 0 {
		return strings.TrimSpace(def.Title[:a])
	} else {
		return ""
	}
}

func cveName(def definition) (cve string) {
	for _, reference := range def.References {
		if reference.Source == "CVE" {
			cve = reference.ID
			break
		}
	}

	return
}

func link(def definition) (link string) {
	// redhat link is wrong
	if name(def) == "RHSA-2016:1064" {
		return cveLink(def)
	}

	for _, reference := range def.References {
		if reference.Source == "RHSA" {
			link = reference.URI
			break
		}
	}

	return
}

func cveLink(def definition) (link string) {
	for _, reference := range def.References {
		if reference.Source == "CVE" {
			link = reference.URI
			break
		}
	}

	return
}

func issuedDate(def definition) time.Time {
	if t, err := time.Parse("2006-01-02", def.Issued.Date); err == nil {
		return t
	} else {
		return time.Time{}
	}
}

func lastModDate(def definition) time.Time {
	if t, err := time.Parse("2006-01-02", def.LastMod.Date); err == nil {
		return t
	} else {
		return time.Time{}
	}
}

func severity(def definition) common.Priority {
	switch strings.ToLower(def.Severity) {
	case "low":
		return common.Low
	case "moderate":
		return common.Medium
	case "important":
		return common.High
	case "critical":
		return common.Critical
	default:
		//log.Warningf("could not determine vulnerability priority from: %s.", prio)
		return common.Unknown
	}
}

// Clean deletes any allocated resources.
func (f *RHELFetcher) Clean() {}
