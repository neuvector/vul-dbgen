package mariner

import (
	"bufio"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/vul-dbgen/common"
	"github.com/vul-dbgen/updater"

	log "github.com/sirupsen/logrus"
)

const (
	marinerFolder = "mariner-vulnerability"
	marinerFile   = "cbl-mariner-1.0-oval.xml"
	notapplicable = "not applicable"
)

var (
	ignoredCriterions = []string{}
)

type MarinerFetcher struct{}

type oval struct {
	Definitions []definition `xml:"definitions>definition"`
	Tests       []test       `xml:"tests>rpminfo_test"`
	Objects     []object     `xml:"objects>rpminfo_object"`
	States      []state      `xml:"states>rpminfo_state"`
}

type definition struct {
	Title        string      `xml:"metadata>title"`
	References   []reference `xml:"metadata>reference"`
	Patchable    string      `xml:"metadata>patchable"`
	AdvisoryDate string      `xml:"metadata>advisory_date"`
	AdvisoryID   string      `xml:"metadata>advisory_id"`
	Severity     string      `xml:"metadata>severity"`
	Description  string      `xml:"metadata>description"`
	Criteria     criteria    `xml:"criteria"`
}

type reference struct {
	Source string `xml:"source,attr"`
	URI    string `xml:"ref_url,attr"`
	ID     string `xml:"ref_id,attr"`
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
	Check   string     `xml:"check,attr"`
	Comment string     `xml:"comment,attr"`
	ID      string     `xml:"id,attr"`
	Version string     `xml:"version,attr"`
	Object  testObject `xml:"object"`
	State   testState  `xml:"state"`
}

type testObject struct {
	ObjectReference string `xml:"object_ref,attr"`
}

type testState struct {
	StateReference string `xml:"state_ref,attr"`
}

type state struct {
	ID      string `xml:"id,attr"`
	Version string `xml:"version,attr"`
	Evr     evr    `xml:"evr"`
}

type evr struct {
	StateDatatype  string `xml:"datatype,attr"`
	StateOperation string `xml:"operation,attr"`
	Body           string `xml:",chardata"`
}

type object struct {
	ID      string   `xml:"id,attr"`
	Version string   `xml:"version,attr"`
	Name    []string `xml:"name"`
}

func init() {
	updater.RegisterFetcher("mariner", &MarinerFetcher{})
}

// FetchUpdate fetches vulnerability updates from the Debian Security Tracker.
func (fetcher *MarinerFetcher) FetchUpdate() (resp updater.FetcherResponse, err error) {
	log.Info("fetching mariner vulnerabilities")
	var reader io.Reader

	//Load file
	file, err := os.Open(fmt.Sprintf("%s/%s/%s", updater.CVESourceRoot, marinerFolder, marinerFile))
	if err != nil {
		return resp, err
	}
	reader = bufio.NewReader(file)

	vulns, err := parseMarinerOval(reader)
	if err != nil {
		return resp, err
	}

	// Collect vulnerabilities.
	for _, v := range vulns {
		if !updater.IgnoreSeverity(v.Severity) {
			resp.Vulnerabilities = append(resp.Vulnerabilities, v)
		}
	}
	log.WithFields(log.Fields{"Vulnerabilities": len(resp.Vulnerabilities)}).Info("fetching mariner done")
	return resp, nil
}

func parseMarinerOval(ovalReader io.Reader) (vulnerabilities []updater.Vulnerability, err error) {
	// Decode the XML.
	var ov oval
	err = xml.NewDecoder(ovalReader).Decode(&ov)
	if err != nil {
		log.Errorf("could not decode Mariner's XML: %s", err)
		err = common.ErrCouldNotParse
		return
	}
	objMap := make(map[string]object)
	for _, obj := range ov.Objects {
		objId, _ := getReferenceNum(obj.ID)
		objMap[objId] = obj
	}
	tstMap := make(map[string]test)
	for _, tst := range ov.Tests {
		tstID, _ := getReferenceNum(tst.ID)
		tstMap[tstID] = tst
	}
	stateMap := make(map[string]state)
	for _, state := range ov.States {
		stateID, _ := getReferenceNum(state.ID)
		stateMap[stateID] = state
	}

	for _, definition := range ov.Definitions {
		cveName := cveName(definition)

		if year, err := common.ParseYear(cveName[4:]); err != nil {
			log.WithFields(log.Fields{"cve": cveName}).Warn("Unable to parse year from CVE name")
			continue
		} else if year < common.FirstYear {
			continue
		}

		vulnerability := updater.Vulnerability{
			Name:        cveName,
			Link:        cveLink(definition),
			Severity:    severity(definition),
			Description: definition.Description,
			IssuedDate:  issuedDate(definition),
		}
		if strings.EqualFold(definition.Patchable, notapplicable) {
			continue
		} else if definition.Patchable == "true" {
			pkgs := toFeatureVersions(cveName, definition.Criteria, stateMap, objMap, tstMap)
			vulnerability.FixedIn = append(vulnerability.FixedIn, pkgs...)
		}

		vulnerabilities = append(vulnerabilities, vulnerability)
	}
	return
}

func getReferenceNum(idstring string) (string, error) {
	results := strings.Split(idstring, ":")
	var result string
	if len(results) == 4 {
		result = results[3]
	} else {
		return "", errors.New("invalid format when parsing criterion test ref")
	}

	return result, nil
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
			possibilities = append(possibilities, possibilityGroup...)
		}
	}
	log.WithFields(log.Fields{"Possibilities": len(possibilities)}).Info("Mariner Possibilities")
	return possibilities
}

func toFeatureVersions(cvename string, criteria criteria, stateMap map[string]state, objMap map[string]object, tstMap map[string]test) []updater.FeatureVersion {
	featureVersionParameters := make(map[string]updater.FeatureVersion)

	possibilities := getPossibilities(cvename, criteria)
	for _, criterions := range possibilities {
		var (
			featureVersion updater.FeatureVersion
		)

		// Attempt to parse package data from trees of criterions.
		for _, criterion := range criterions {
			criterionTestVersion, _ := getReferenceNum(criterion.TestRef)
			test := tstMap[criterionTestVersion]
			objectID, err := getReferenceNum(test.Object.ObjectReference)
			if err != nil {
				fmt.Println(err)
			}
			stateID, err := getReferenceNum(test.State.StateReference)
			if err != nil {
				fmt.Println(err)
			}
			pkgName := objMap[objectID].Name
			state := stateMap[stateID]
			object := objMap[objectID]
			featureVersion.Feature.Name = pkgName[0]
			//versionStr := strings.Replace(state.Evr.Body, ".cm1", "", 1)
			versionStr := state.Evr.Body
			featureVersion.Feature.Namespace = "mariner:1.0"
			featureVersion.Version, err = common.NewVersion(versionStr)
			if err != nil {
				log.WithFields(log.Fields{"cve": cvename, "error": err, "comment": criterion.Comment, "version": object.Version}).Warn("Failed to parse release version")
			}
		}

		if featureVersion.Feature.Namespace != "" && featureVersion.Feature.Name != "" && featureVersion.Version.String() != "" {
			featureVersionParameters[featureVersion.Feature.Namespace+":"+featureVersion.Feature.Name] = featureVersion
		}
	}

	// Convert the map to slice.
	var featureVersionParametersArray []updater.FeatureVersion
	for _, fv := range featureVersionParameters {
		featureVersionParametersArray = append(featureVersionParametersArray, fv)
	}

	return featureVersionParametersArray
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
	defTime := strings.Split(def.AdvisoryDate, "T")[0]
	if t, err := time.Parse("2006-01-02", defTime); err == nil {
		return t
	} else {
		return time.Time{}
	}
}

func severity(def definition) common.Priority {
	switch strings.ToLower(def.Severity) {
	case "low":
		return common.Low
	case "medium":
		return common.Medium
	case "high":
		return common.High
	case "critical":
		return common.Critical
	default:
		return common.Unknown
	}
}

// Clean deletes any allocated resources.
func (fetcher *MarinerFetcher) Clean() {}
