package ubuntu

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/vul-dbgen/common"
	"github.com/vul-dbgen/updater"
	"github.com/vul-dbgen/share"
)

const (
	trackerURI        = "https://launchpad.net/ubuntu-cve-tracker"
	trackerRepository = "https://git.launchpad.net/ubuntu-cve-tracker"
	cveURL            = "http://people.ubuntu.com/~ubuntu-security/cve/%s"
	ubuntuFolder      = "ubuntu-cve-tracker"
	maxRetryTimes     = 5
)

var (
	ubuntuIgnoredReleases = map[string]struct{}{
		"devel": {},

		"dapper":   {},
		"edgy":     {},
		"feisty":   {},
		"gutsy":    {},
		"hardy":    {},
		"intrepid": {},
		"jaunty":   {},
		"karmic":   {},
		"lucid":    {},
		"maverick": {},
		"natty":    {},
		"oneiric":  {},
		"saucy":    {},

		"vivid/ubuntu-core":          {},
		"vivid/stable-phone-overlay": {},

		// Syntax error
		"Patches": {},
		// Product
		"product": {},
	}

	affectsCaptureRegexp      = regexp.MustCompile(`(?P<release>.*)_(?P<package>.*): (?P<status>[^\s]*)( \(+(?P<note>[^()]*)\)+)?`)
	affectsCaptureRegexpNames = affectsCaptureRegexp.SubexpNames()

	// ErrFilesystem is returned when a fetcher fails to interact with the local filesystem.
	ErrFilesystem = errors.New("updater/fetchers: something went wrong when interacting with the fs")
)

// UbuntuFetcher implements updater.Fetcher and gets vulnerability updates from
// the Ubuntu CVE Tracker.
type UbuntuFetcher struct {
	repositoryLocalPath string
}

func init() {
	updater.RegisterFetcher("ubuntu", &UbuntuFetcher{})
}

// FetchUpdate gets vulnerability updates from the Ubuntu CVE Tracker.
func (fetcher *UbuntuFetcher) FetchUpdate() (resp updater.FetcherResponse, err error) {
	log.Info("fetching Ubuntu vulnerabilities")

	dbDir := fmt.Sprintf("%s%s", updater.CVESourceRoot, ubuntuFolder)
	if info, err := os.Stat(dbDir); err == nil && info.IsDir() {
		log.Debug("Use local Ubuntu database")
		fetcher.repositoryLocalPath = dbDir
	} else {
		log.WithFields(log.Fields{"error": err}).Error("Download Ubuntu database from Internet")

		defer fetcher.Clean()
		// Pull the bzr repository.
		retry := 0
		for retry <= maxRetryTimes {
			err = fetcher.pullRepository()
			if err == nil {
				break
			}
			if err != nil && retry >= maxRetryTimes {
				return resp, err
			}
			retry++
			log.WithFields(log.Fields{"retry": retry, "error": err}).Debug("Pull ubuntu repository")
		}
	}

	var revisionNumber int
	var dbRevisionNumber string

	// Get the list of vulnerabilities that we have to update.
	modifiedCVE, err := collectModifiedVulnerabilities(revisionNumber, dbRevisionNumber, fetcher.repositoryLocalPath)
	if err != nil {
		return resp, err
	}

	notes := make(map[string]struct{})
	for cvePath := range modifiedCVE {
		// Open the CVE file.
		file, err := os.Open(fetcher.repositoryLocalPath + "/" + cvePath)
		if err != nil {
			// This can happen when a file is modified and then moved in another
			// commit.
			continue
		}

		// Parse the vulnerability.
		v, unknownReleases, err := parseUbuntuCVE(file)
		if err != nil {
			return resp, err
		}

		if !updater.IgnoreSeverity(v.Severity) {
			// Add the vulnerability to the response.
			upstreamCalibration(&v)
			if len(v.FixedIn) > 0 {
				resp.Vulnerabilities = append(resp.Vulnerabilities, v)
			}
		}
		// Store any unknown releases as notes.
		for k := range unknownReleases {
			note := fmt.Sprintf("Ubuntu %s is not mapped to any version number (eg. trusty->14.04). Please update me.", k)
			notes[note] = struct{}{}

			// If we encountered unknown Ubuntu release, we don't want the revision
			// number to be considered as managed.
			dbRevisionNumberInt, _ := strconv.Atoi(dbRevisionNumber)
			revisionNumber = dbRevisionNumberInt
		}

		// Close the file manually.
		//
		// We do that instead of using defer because defer works on a function-level scope.
		// We would open many files and close them all at once at the end of the function,
		// which could lead to exceed fs.file-max.
		file.Close()
	}

	if len(resp.Vulnerabilities) == 0 {
		log.Error("Ubuntu update CVE FAIL")
		return resp, fmt.Errorf("Ubuntu update CVE FAIL")
	}
	log.WithFields(log.Fields{"Vulnerabilities": len(resp.Vulnerabilities)}).Info("fetching Ubuntu done")
	return
}

func (fetcher *UbuntuFetcher) pullRepository() (err error) {
	// Determine whether we should branch or pull.
	if _, pathExists := os.Stat(fetcher.repositoryLocalPath); fetcher.repositoryLocalPath == "" || os.IsNotExist(pathExists) {
		// Create a temporary folder to store the repository.
		if fetcher.repositoryLocalPath, err = ioutil.TempDir(os.TempDir(), "ubuntu-cve-tracker"); err != nil {
			return ErrFilesystem
		}
	}

	// Pull repository.
	if out, err := utils.Exec(fetcher.repositoryLocalPath, "git", "clone", trackerRepository, "./"); err != nil {
		os.RemoveAll(fetcher.repositoryLocalPath)

		log.Errorf("could not pull Ubuntu repository: %s. output: %s", err, out)
		return common.ErrCouldNotDownload
	}

	return nil
}

func getRevisionNumber(pathToRepo string) (int, error) {
	out, err := utils.Exec(pathToRepo, "bzr", "revno")
	if err != nil {
		log.Errorf("could not get Ubuntu repository's revision number: %s. output: %s", err, out)
		return 0, common.ErrCouldNotDownload
	}
	revno, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		log.Errorf("could not parse Ubuntu repository's revision number: %s. output: %s", err, out)
		return 0, common.ErrCouldNotDownload
	}
	return revno, nil
}

func collectModifiedVulnerabilities(revision int, dbRevision, repositoryLocalPath string) (map[string]struct{}, error) {
	modifiedCVE := make(map[string]struct{})

	// Handle a brand new database.
	if dbRevision == "" {
		for _, folder := range []string{"active", "retired"} {
			d, err := os.Open(repositoryLocalPath + "/" + folder)
			if err != nil {
				log.Errorf("could not open Ubuntu vulnerabilities repository's folder: %s", err)
				return nil, ErrFilesystem
			}

			// Get the FileInfo of all the files in the directory.
			names, err := d.Readdirnames(-1)
			if err != nil {
				log.Errorf("could not read Ubuntu vulnerabilities repository's folder:: %s.", err)
				return nil, ErrFilesystem
			}

			// Add the vulnerabilities to the list.
			for _, name := range names {
				if !strings.HasPrefix(name, "CVE-") {
					continue
				} else if year, err := common.ParseYear(name[4:]); err != nil {
					continue
				} else if year < common.FirstYear {
					continue
				}

				modifiedCVE[folder+"/"+name] = struct{}{}
			}

			// Close the file manually.
			//
			// We do that instead of using defer because defer works on a function-level scope.
			// We would open many files and close them all at once at the end of the function,
			// which could lead to exceed fs.file-max.
			d.Close()
		}

		return modifiedCVE, nil
	}

	// Handle an up to date database.
	dbRevisionInt, _ := strconv.Atoi(dbRevision)
	if revision == dbRevisionInt {
		log.Debug("no Ubuntu update")
		return modifiedCVE, nil
	}

	// Handle a database that needs upgrading.
	out, err := utils.Exec(repositoryLocalPath, "bzr", "log", "--verbose", "-r"+strconv.Itoa(dbRevisionInt+1)+"..", "-n0")
	if err != nil {
		log.Errorf("could not get Ubuntu vulnerabilities repository logs: %s. output: %s", err, out)
		return nil, common.ErrCouldNotDownload
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if strings.Contains(text, "CVE-") && (strings.HasPrefix(text, "active/") || strings.HasPrefix(text, "retired/")) {
			if strings.Contains(text, " => ") {
				text = text[strings.Index(text, " => ")+4:]
			}
			modifiedCVE[text] = struct{}{}
		}
	}

	return modifiedCVE, nil
}

func parseUbuntuCVE(fileContent io.Reader) (vulnerability updater.Vulnerability, unknownReleases map[string]struct{}, err error) {
	unknownReleases = make(map[string]struct{})
	readingDescription := false
	scanner := bufio.NewScanner(fileContent)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip any comments.
		if strings.HasPrefix(line, "#") {
			continue
		}

		// Parse the name.
		if strings.HasPrefix(line, "Candidate:") {
			vulnerability.Name = strings.TrimSpace(strings.TrimPrefix(line, "Candidate:"))
			vulnerability.Link = fmt.Sprintf(cveURL, vulnerability.Name)
			continue
		}

		// Parse the priority.
		if strings.HasPrefix(line, "Priority:") {
			priority := strings.TrimSpace(strings.TrimPrefix(line, "Priority:"))

			// Handle syntax error: Priority: medium (heap-protector)
			if strings.Contains(priority, " ") {
				priority = priority[:strings.Index(priority, " ")]
			}

			vulnerability.Severity = ubuntuPriorityToSeverity(priority)
			vulnerability.FeedRating = priority
			continue
		}

		// Parse the description.
		if strings.HasPrefix(line, "Description:") {
			readingDescription = true
			vulnerability.Description = strings.TrimSpace(strings.TrimPrefix(line, "Description:")) // In case there is a formatting error and the description starts on the same line
			continue
		}
		if readingDescription {
			if strings.HasPrefix(line, "Ubuntu-Description:") || strings.HasPrefix(line, "Notes:") || strings.HasPrefix(line, "Bugs:") || strings.HasPrefix(line, "Priority:") || strings.HasPrefix(line, "Discovered-by:") || strings.HasPrefix(line, "Assigned-to:") {
				readingDescription = false
			} else {
				vulnerability.Description = vulnerability.Description + " " + line
				continue
			}
		}

		// Try to parse the package that the vulnerability affects.
		affectsCaptureArr := affectsCaptureRegexp.FindAllStringSubmatch(line, -1)
		if len(affectsCaptureArr) > 0 {
			affectsCapture := affectsCaptureArr[0]

			md := map[string]string{}
			for i, n := range affectsCapture {
				md[affectsCaptureRegexpNames[i]] = strings.TrimSpace(n)
			}

			// Ignore Linux kernels.
			//if strings.HasPrefix(md["package"], "linux") {
			//	continue
			//}

			/*
				if vulnerability.Name == "CVE-2020-1938" {
					log.WithFields(log.Fields{"package": md["package"], "status": md["status"], "release": md["release"], "note": md["node"]}).Info()
				}
			*/

			// Only consider the package if its status is needed, active, deferred, not-affected or
			// released. Ignore DNE (package does not exist), needs-triage, ignored, pending.
			if md["status"] == "needed" || md["status"] == "active" || md["status"] == "deferred" || md["status"] == "released" || md["status"] == "not-affected" {
				if _, isReleaseIgnored := ubuntuIgnoredReleases[md["release"]]; isReleaseIgnored {
					continue
				}
				if _, isReleaseKnown := common.UbuntuReleasesMapping[md["release"]]; !isReleaseKnown {
					unknownReleases[md["release"]] = struct{}{}
					continue
				}

				var version common.Version
				if md["status"] == "released" {
					if md["note"] != "" {
						noteStr := md["note"]

						if !strings.Contains(noteStr, ",") {
							var err error
							version, err = common.NewVersion(noteStr)
							if err != nil {
								//log.Warningf("could not parse package version (%s)'%s': %s. skipping", vulnerability.Name, md["note"], err)
							}
						} else if md["release"] != "upstream" {
							log.Warningf("complex version (%s)'%s'. skipping", vulnerability.Name, md)
						}
					}
				} else if md["status"] == "not-affected" {
					version = common.MinVersion
				} else {
					version = common.MaxVersion
				}
				if version.String() == "" {
					continue
				}

				// Create and add the new package.
				featureVersion := updater.FeatureVersion{
					Feature: updater.Feature{
						Namespace: "ubuntu:" + common.UbuntuReleasesMapping[md["release"]],
						Name:      md["package"],
					},
					Version: version,
				}
				vulnerability.FixedIn = append(vulnerability.FixedIn, featureVersion)
			}
		}
	}

	// Trim extra spaces in the description
	vulnerability.Description = strings.TrimSpace(vulnerability.Description)

	// If no link has been provided (CVE-2006-NNN0 for instance), add the link to the tracker
	if vulnerability.Link == "" {
		vulnerability.Link = trackerURI
	}

	// If no priority has been provided (CVE-2007-0667 for instance), set the priority to Unknown
	if vulnerability.Severity == "" {
		vulnerability.Severity = common.Unknown
	}

	return
}

func ubuntuPriorityToSeverity(priority string) common.Priority {
	switch priority {
	case "untriaged":
		return common.Unknown
	case "negligible":
		return common.Negligible
	case "low":
		return common.Low
	case "medium":
		return common.Medium
	case "high":
		return common.High
	case "critical":
		return common.Critical
	}

	log.Warningf("Could not determine a vulnerability priority from: %s", priority)
	return common.Unknown
}

type feactureShort struct {
	Name    string `json:"N"`
	Version string `json:"V"`
}

var calibrateMap = map[string]feactureShort{
	"CVE-2018-1087":    {Name: "", Version: "4.17"},
	"CVE-2017-1000405": {Name: "", Version: "4.14"},
	"CVE-2017-17712":   {Name: "", Version: "4.14.6"},
	"CVE-2017-16996":   {Name: "", Version: "4.14.8"},
	"CVE-2017-16995":   {Name: "", Version: "4.14.8"},
}

func upstreamCalibration(v *updater.Vulnerability) {
	// skip openssl in upstream
	var newFix []updater.FeatureVersion
	for _, fx := range v.FixedIn {
		if !strings.Contains(fx.Feature.Namespace, "upstream") {
			newFix = append(newFix, fx)
			continue
		}
		// we have separated openssl database, so skip it
		if fx.Feature.Name == "openssl" {
			continue
		}
		if strings.Contains(fx.Version.String(), "ubuntu") {
			continue
		}
		// fix linux kernel false cve reported on coreos
		if calib, ok := calibrateMap[v.Name]; ok {
			if calib.Name == "" || calib.Name == fx.Feature.Name {
				fx.Version, _ = common.NewVersion(calib.Version)
			}
		}
		newFix = append(newFix, fx)
	}
	v.FixedIn = newFix
}

// Clean deletes any allocated resources.
func (fetcher *UbuntuFetcher) Clean() {
	os.RemoveAll(fetcher.repositoryLocalPath)
}
