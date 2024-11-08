package suse

import (
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/vul-dbgen/common"
	utils "github.com/vul-dbgen/share"
	"github.com/vul-dbgen/updater"
)

type ovalInfo struct {
	filename string
	name     string
	nsPrefix string // Must start with sles:
}

var (
	ovals []ovalInfo = []ovalInfo{
		ovalInfo{"suse/suse.linux.enterprise.server.15.xml.gz", "SUSE Linux Enterprise Server 15 ", "sles:"},
		ovalInfo{"suse/suse.linux.enterprise.server.12.xml.gz", "SUSE Linux Enterprise Server 12 ", "sles:"},
		ovalInfo{"suse/suse.linux.enterprise.server.11.xml.gz", "SUSE Linux Enterprise Server 11 ", "sles:"},
		ovalInfo{"suse/opensuse.leap.15.5.xml.gz", "openSUSE Leap 15.5 ", "sles:l"},
		ovalInfo{"suse/opensuse.leap.15.4.xml.gz", "openSUSE Leap 15.4 ", "sles:l"},
		ovalInfo{"suse/opensuse.leap.15.3.xml.gz", "openSUSE Leap 15.3 ", "sles:l"},
		ovalInfo{"suse/opensuse.leap.15.2.xml.gz", "openSUSE Leap 15.2 ", "sles:l"},
		ovalInfo{"suse/opensuse.leap.15.1.xml.gz", "openSUSE Leap 15.1 ", "sles:l"},
		ovalInfo{"suse/opensuse.leap.15.0.xml.gz", "openSUSE Leap 15.0 ", "sles:l"},
		ovalInfo{"suse/opensuse.tumbleweed.xml.gz", "openSUSE Tumbleweed ", "sles:tw"},
		ovalInfo{"suse/suse.liberty.linux.7.xml.gz", "SUSE Liberty Linux 7", "sles:lib"},
		ovalInfo{"suse/suse.liberty.linux.8.xml.gz", "SUSE Liberty Linux 8", "sles:lib"},
		ovalInfo{"suse/suse.liberty.linux.9.xml.gz", "SUSE Liberty Linux 9", "sles:lib"},
	}

	noVersion = map[string]struct{}{
		"suse/opensuse.tumbleweed.xml.gz": {},
	}

	LibertyFirstYear = 2004
	cveMatch         = "CVE-[0-9]+-[0-9]+"
)

// Feed format
type ovalFeed struct {
	Definitions []definition `xml:"definitions>definition"`
	Tests       []test       `xml:"tests>rpminfo_test"`
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

type test struct {
	ID      string `xml:"id,attr"`
	Comment string `xml:"comment,attr"`
}

// --

type testInfo struct {
	name    string
	op      string
	version common.Version
	verStr  string
}

type SuseFetcher struct{}

func init() {
	updater.RegisterFetcher("suse", &SuseFetcher{})
}

func (f *SuseFetcher) FetchUpdate() (resp updater.FetcherResponse, err error) {
	log.Info("fetching SUSE vulnerabilities")

	for _, oval := range ovals {
		if r, err := f.fetchOvalData(&oval); err == nil {
			resp.Vulnerabilities = append(resp.Vulnerabilities, r.Vulnerabilities...)
		}
	}

	if len(resp.Vulnerabilities) == 0 {
		log.Error("Failed to fetch SUSE oval feed")
		return resp, fmt.Errorf("Failed to fetch SUSE oval feeed")
	}

	log.WithFields(log.Fields{"Vulnerabilities": len(resp.Vulnerabilities)}).Info("Fetch SUSE done")
	return resp, nil
}

func (f *SuseFetcher) fetchOvalData(o *ovalInfo) (updater.FetcherResponse, error) {
	log.WithFields(log.Fields{"file": o.filename}).Info("fetching SUSE oval feed")

	var resp updater.FetcherResponse

	fullname := fmt.Sprintf("%s%s", common.CVESourceRoot, o.filename)
	file, err := os.Open(fullname)
	if err != nil {
		log.WithFields(log.Fields{"file": o.filename}).Error("Failed to open the feed file")
		return resp, fmt.Errorf("Unabled to fetch the oval feed")
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		log.WithFields(log.Fields{"file": o.filename}).Error("Failed to create feed reader")
		return resp, fmt.Errorf("Unabled to fetch the oval feed")
	}
	defer gzr.Close()

	vs, err := parseOVAL(o, gzr)

	// Collect vulnerabilities.
	for _, v := range vs {
		common.DEBUG_VULN(&v, "suse")

		resp.Vulnerabilities = append(resp.Vulnerabilities, v)
	}

	if len(resp.Vulnerabilities) == 0 {
		log.WithFields(log.Fields{"file": o.filename}).Error("No vulnerability read")
		return resp, fmt.Errorf("Failed to update SUSE oval feed")
	}

	log.WithFields(log.Fields{"Vulnerabilities": len(resp.Vulnerabilities), "file": o.filename}).Info("fetching SUSE oval")
	return resp, nil
}

func parseOVAL(o *ovalInfo, ovalReader io.Reader) ([]common.Vulnerability, error) {
	var ov ovalFeed
	var vulnerabilities []common.Vulnerability

	err := xml.NewDecoder(ovalReader).Decode(&ov)
	if err != nil {
		log.WithFields(log.Fields{"file": o.filename, "error": err}).Error("Failed to decode XML")
		return vulnerabilities, common.ErrCouldNotParse
	}

	testMap := make(map[string]*testInfo)
	for _, test := range ov.Tests {
		if ti := parseTestFeatureVersion(&test); ti != nil {
			testMap[test.ID] = ti
		}
	}

	// Iterate over the definitions and collect any vulnerabilities that affect
	// at least one package.
	for _, definition := range ov.Definitions {
		cvename := name(definition)
		dedup := utils.NewSet()

		if strings.HasPrefix(cvename, "CVE-") {
			if year, e := common.ParseYear(cvename[4:]); e != nil {
				log.WithFields(log.Fields{"cve": cvename}).Warn("Unexpected vulnerability year")
				continue
			} else if year < common.FirstYear && !strings.Contains(o.filename, "liberty") {
				continue
			} else if year < LibertyFirstYear && strings.Contains(o.filename, "liberty") {
				continue
			}
		} else {
			log.WithFields(log.Fields{"cve": cvename}).Warn("Unexpected vulnerability name")
			continue
		}

		pkgs := parsePackageVersions(o, cvename, definition.Criteria, testMap)

		if len(pkgs) > 0 {
			vulnerability := common.Vulnerability{
				Name:        cvename,
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
			// 	log.WithFields(log.Fields{"cve": cvename, "file": o.filename}).Warn("Unknown severity")
			// }
			for _, p := range pkgs {
				vulnerability.FixedIn = append(vulnerability.FixedIn, p)
			}
			for _, r := range definition.Cves {
				reg := regexp.MustCompile(cveMatch)
				cve := reg.FindString(r.ID)
				if cve != "" && !dedup.Contains(cve) {
					dedup.Add(cve)
					vulnerability.CVEs = append(vulnerability.CVEs, common.CVE{
						Name: cve,
					})
				}
			}
			if vulnerability.IssuedDate.IsZero() {
				vulnerability.IssuedDate = vulnerability.LastModDate
			}
			if vulnerability.LastModDate.IsZero() {
				vulnerability.LastModDate = vulnerability.IssuedDate
			}
			vulnerabilities = append(vulnerabilities, vulnerability)

			// if vulnerability.Name == cveToDebug {
			// 	log.WithFields(log.Fields{"v": vulnerability}).Warn()
			// }
		}
	}
	return vulnerabilities, nil
}

func getCriterions(node criteria) [][]criterion {
	// Filter useless criterions.
	var criterions []criterion
	for _, c := range node.Criterions {
		criterions = append(criterions, c)
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

func parseTestFeatureVersion(t *test) *testInfo {
	var info testInfo
	var err error

	ops := []string{"==", "<=", ">=", "<", ">"} // make sure longer pattern first
	if s := strings.Index(t.Comment, " "); s != -1 {
		info.name = t.Comment[:s]
		for _, op := range ops {
			if o := strings.Index(t.Comment[s+1:], op); o != -1 {
				info.op = op

				v := t.Comment[s+1+o+len(op):]
				if s = strings.Index(v, " "); s != -1 {
					v = v[:s]
				}
				if info.version, err = common.NewVersion(v); err == nil {
					info.verStr = v
					return &info
				} else {
					log.WithFields(log.Fields{"test": t.ID, "comment": t.Comment}).Warn("Failed to parse package version")
					return nil
				}
			}
		}

		// log.WithFields(log.Fields{"test": t.ID, "comment": t.Comment}).Warn("Failed to parse package version operator")
		return nil
	}

	log.WithFields(log.Fields{"test": t.ID, "comment": t.Comment}).Warn("Fialed to parse test comment")
	return nil
}

func parsePackageVersions(o *ovalInfo, cvename string, criteria criteria, testMap map[string]*testInfo) []common.FeatureVersion {
	fvMap := make(map[string]common.FeatureVersion)

	possibilities := getPossibilities(cvename, criteria)
	for _, criterions := range possibilities {
		var fv common.FeatureVersion

		// Attempt to parse package data from trees of criterions.
		for _, c := range criterions {
			if strings.HasPrefix(c.Comment, o.name) && strings.Contains(c.Comment, " is installed") {
				if ti, ok := testMap[c.TestRef]; ok {
					if _, ok := noVersion[o.filename]; ok {
						fv.Feature.Namespace = o.nsPrefix
					} else {
						fv.Feature.Namespace = fmt.Sprintf("%s%s", o.nsPrefix, ti.version)
					}
				}
			} else if !strings.HasPrefix(c.Comment, "SUSE") && (strings.Contains(c.Comment, " is installed") || strings.Contains(c.Comment, " is not affected")) {
				// This is the package line
				if ti, ok := testMap[c.TestRef]; ok {
					if ti.verStr == "0" {
						// not affected for all version
						continue
					}

					fv.Version = ti.version
					fv.Feature.Name = ti.name
				}
			}
		}

		if fv.Feature.Namespace != "" && fv.Feature.Name != "" && fv.Version.String() != "" {
			fvMap[fv.Feature.Namespace+":"+fv.Feature.Name] = fv
		} else {
			//log.WithFields(log.Fields{"Namespace": fv.Feature.Namespace,
			//	"Feature": fv.Feature.Name,
			//	"Version": fv.Version.String(),
			//}).Warn("criterions")
			//log.WithFields(log.Fields{"criteria": criterions}).Warn("Failed to determine a valid package from criterions")
		}
	}

	// Convert the map to slice.
	var fvList []common.FeatureVersion
	for _, fv := range fvMap {
		fvList = append(fvList, fv)
	}

	return fvList
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
		return def.Title
	}
}

func link(def definition) (link string) {
	for _, reference := range def.References {
		if reference.Source == "SUSE CVE" {
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
func (f *SuseFetcher) Clean() {}
