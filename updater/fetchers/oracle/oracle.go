package oracle

import (
	"bytes"
	"compress/bzip2"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/vul-dbgen/common"
	"github.com/vul-dbgen/updater"
)

const (
	firstConsideredELSA = 7

	ovalURI    = "https://linux.oracle.com/security/oval/"
	retryTimes = 5
)

var (
	ignoredCriterions = []string{
		" is signed with the Oracle Linux",
		".ksplice1.",
	}

	elsaRegexp = regexp.MustCompile(`href="(com\.oracle\.elsa-(?:all|ol(?:6|7|8|9|10))\.xml\.bz2)"`)
)

type oval struct {
	Definitions []definition `xml:"definitions>definition"`
}

type definition struct {
	Title       string      `xml:"metadata>title"`
	Description string      `xml:"metadata>description"`
	References  []reference `xml:"metadata>reference"`
	Criteria    criteria    `xml:"criteria"`
	Severity    string      `xml:"metadata>advisory>severity"`
	Issued      issued      `xml:"metadata>advisory>issued"`
	LastMod     updated     `xml:"metadata>advisory>updated"`
	Cves        []cve       `xml:"metadata>advisory>cve"`
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

type OracleFetcher struct{}

func init() {
	updater.RegisterFetcher("oracle", &OracleFetcher{})
}

func (f *OracleFetcher) FetchUpdate() (resp updater.FetcherResponse, err error) {
	log.Info("fetching Oracle vulnerabilities")

	req, err := http.NewRequest("GET", ovalURI, nil)
	if err != nil {
		return resp, err
	}
	req.Header.Add("User-Agent", "dbgen")
	client := http.Client{}
	r, err := client.Do(req)
	if err != nil {
		log.Errorf("could not download Oracle's directory: %s", err)
		return resp, common.ErrCouldNotDownload
	}
	defer r.Body.Close()

	indexBody, err := io.ReadAll(r.Body)
	if err != nil {
		log.Errorf("could not read Oracle's directory: %s", err)
		return resp, common.ErrCouldNotDownload
	}

	feedFiles := listFeedFiles(indexBody)
	if len(feedFiles) == 0 {
		log.Error("Failed to find Oracle oval feeds")
		return resp, fmt.Errorf("Failed to find Oracle oval feeds")
	}

	vulnMap := make(map[string]common.Vulnerability)

	for i, elsaFile := range feedFiles {
		var vs []common.Vulnerability

		retry := 0
		for retry <= retryTimes {
			rurl := ovalURI + elsaFile

			client := http.Client{}
			req, err := http.NewRequest("GET", rurl, nil)
			if err != nil {
				return resp, err
			}
			req.Header.Add("User-Agent", "dbgen")
			if r, err := client.Do(req); err == nil {
				vs, err = parseBZ2ELSA(elsaFile, r.Body)

				r.Body.Close()
				if err == nil {
					break
				} else if retry == retryTimes {
					log.Errorf("could not parse Oracle's xml database: %s", err)
					break
				}
			} else {
				if retry == retryTimes {
					log.Errorf("could not download Oracle's update file: %s", err)
					break
				}
			}

			time.Sleep(time.Second * 2)
			retry++
		}

		// Collect vulnerabilities.
		for _, v := range vs {
			mergeVulnerability(vulnMap, v)
		}

		// Pause to prevent the website from blacklisting us.
		if i%20 == 0 {
			time.Sleep(time.Second * 2)
		}
	}

	for _, v := range vulnMap {
		resp.Vulnerabilities = append(resp.Vulnerabilities, v)
	}

	if len(resp.Vulnerabilities) == 0 {
		log.Error("Failed to fetch Oracle oval feed")
		return resp, fmt.Errorf("Failed to fetch Oracle oval feed")
	}

	log.WithFields(log.Fields{"Vulnerabilities": len(resp.Vulnerabilities)}).Info("Fetch Oracle done")
	return resp, nil
}

func parseBZ2ELSA(elsa string, compressedReader io.Reader) ([]common.Vulnerability, error) {
	return parseELSA(elsa, bzip2.NewReader(compressedReader))
}

func parseELSA(elsa string, ovalReader io.Reader) (vulnerabilities []common.Vulnerability, err error) {
	body, err := io.ReadAll(ovalReader)
	if err != nil {
		return nil, err
	}

	trimmed := bytes.TrimSpace(body)
	if bytes.HasPrefix(trimmed, []byte("<!DOCTYPE html")) || bytes.HasPrefix(trimmed, []byte("<html")) {
		log.WithFields(log.Fields{"elsa": elsa}).Warn("Oracle ELSA returned HTML instead of XML, skipping")
		return nil, nil
	}

	// Decode the XML.
	var ov oval
	err = xml.NewDecoder(bytes.NewReader(body)).Decode(&ov)
	if err != nil {
		if bytes.Contains(bytes.ToLower(trimmed), []byte("<html")) || bytes.Contains(bytes.ToLower(trimmed), []byte("<body")) {
			log.WithFields(log.Fields{"elsa": elsa}).Warn("Oracle ELSA returned non-XML content, skipping")
			return nil, nil
		}
		log.Errorf("could not decode Oracle's XML: %s", err)
		err = common.ErrCouldNotParse
		return
	}

	// Iterate over the definitions and collect any vulnerabilities that affect
	// at least one package.
	for _, definition := range ov.Definitions {
		nameId := name(definition)

		pkgs := toFeatureVersions(nameId, definition.Criteria)
		if len(pkgs) > 0 {
			vulnerability := common.Vulnerability{
				Name:        nameId,
				Link:        link(definition),
				Severity:    severity(definition),
				Description: description(definition),
				IssuedDate:  issuedDate(definition),
				LastModDate: lastModDate(definition),
			}
			if vulnerability.Link == "" {
				vulnerability.Link = cveLink(definition)
			}
			// if vulnerability.Severity == common.Unknown {
			// 	log.WithFields(log.Fields{"nameId": nameId, "elsa": elsa}).Error("Unknown severity")
			// }
			for _, p := range pkgs {
				vulnerability.FixedIn = append(vulnerability.FixedIn, p)
			}
			for _, r := range definition.Cves {
				vulnerability.CVEs = append(vulnerability.CVEs, common.CVE{
					Name: r.ID,
				})
			}
			if vulnerability.IssuedDate.IsZero() {
				vulnerability.IssuedDate = vulnerability.LastModDate
			}
			if vulnerability.LastModDate.IsZero() {
				vulnerability.LastModDate = vulnerability.IssuedDate
			}
			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}

	return
}

func listFeedFiles(indexBody []byte) []string {
	matches := elsaRegexp.FindAllSubmatch(indexBody, -1)
	files := make([]string, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		name := string(match[1])
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		files = append(files, name)
	}

	sort.Strings(files)
	return files
}

func mergeVulnerability(vulnMap map[string]common.Vulnerability, v common.Vulnerability) {
	if existing, ok := vulnMap[v.Name]; ok {
		existing.FixedIn = mergeFeatureVersions(existing.FixedIn, v.FixedIn)
		existing.CVEs = mergeCVEs(existing.CVEs, v.CVEs)
		if existing.Description == "" {
			existing.Description = v.Description
		}
		if existing.Link == "" {
			existing.Link = v.Link
		}
		if existing.Severity == common.Unknown {
			existing.Severity = v.Severity
		}
		if existing.IssuedDate.IsZero() || (!v.IssuedDate.IsZero() && v.IssuedDate.Before(existing.IssuedDate)) {
			existing.IssuedDate = v.IssuedDate
		}
		if existing.LastModDate.IsZero() || v.LastModDate.After(existing.LastModDate) {
			existing.LastModDate = v.LastModDate
		}
		vulnMap[v.Name] = existing
		return
	}

	v.FixedIn = mergeFeatureVersions(nil, v.FixedIn)
	v.CVEs = mergeCVEs(nil, v.CVEs)
	vulnMap[v.Name] = v
}

func mergeFeatureVersions(existing []common.FeatureVersion, incoming []common.FeatureVersion) []common.FeatureVersion {
	merged := make([]common.FeatureVersion, 0, len(existing)+len(incoming))
	seen := make(map[string]struct{}, len(existing)+len(incoming))

	for _, fv := range existing {
		key := fv.Feature.Namespace + ":" + fv.Feature.Name + ":" + fv.Version.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, fv)
	}
	for _, fv := range incoming {
		key := fv.Feature.Namespace + ":" + fv.Feature.Name + ":" + fv.Version.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, fv)
	}

	return merged
}

func mergeCVEs(existing []common.CVE, incoming []common.CVE) []common.CVE {
	merged := make([]common.CVE, 0, len(existing)+len(incoming))
	seen := make(map[string]struct{}, len(existing)+len(incoming))

	for _, cve := range existing {
		if _, ok := seen[cve.Name]; ok {
			continue
		}
		seen[cve.Name] = struct{}{}
		merged = append(merged, cve)
	}
	for _, cve := range incoming {
		if _, ok := seen[cve.Name]; ok {
			continue
		}
		seen[cve.Name] = struct{}{}
		merged = append(merged, cve)
	}

	return merged
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

func toFeatureVersions(cvename string, criteria criteria) []common.FeatureVersion {
	featureVersionParameters := make(map[string]common.FeatureVersion)

	possibilities := getPossibilities(cvename, criteria)
	for _, criterions := range possibilities {
		var (
			featureVersion common.FeatureVersion
			osVersion      int
			err            error
		)

		// Attempt to parse package data from trees of criterions.
		for _, c := range criterions {
			if strings.Contains(c.Comment, " is installed") {
				const prefixLen = len("Oracle Linux ")
				a := strings.Index(c.Comment[prefixLen:], " ")
				osVersion, err = strconv.Atoi(strings.TrimSpace(c.Comment[prefixLen : prefixLen+a]))
				if err != nil {
					log.WithFields(log.Fields{"cve": cvename, "error": err, "comment": c.Comment}).Warn("Failed to parse release version")
				}
			} else if strings.Contains(c.Comment, " is earlier than ") {
				const prefixLen = len(" is earlier than ")
				featureVersion.Feature.Name = strings.TrimSpace(c.Comment[:strings.Index(c.Comment, " is earlier than ")])
				verStr := c.Comment[strings.Index(c.Comment, " is earlier than ")+prefixLen:]
				featureVersion.Version, err = common.NewVersion(verStr)
				if err != nil {
					log.WithFields(log.Fields{"cve": cvename, "error": err, "comment": c.Comment, "version": verStr}).Warn("Failed to parse release version")
				}
			}
		}

		if osVersion >= firstConsideredELSA {
			featureVersion.Feature.Namespace = "oracle" + ":" + strconv.Itoa(osVersion)
		} else {
			continue
		}

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
	desc = strings.ReplaceAll(def.Description, "\n\n\n", " ")
	desc = strings.ReplaceAll(desc, "\n\n", " ")
	desc = strings.ReplaceAll(desc, "\n", " ")
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
	for _, reference := range def.References {
		if reference.Source == "elsa" {
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
func (f *OracleFetcher) Clean() {}
