package amazon

import (
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/k3a/html2text"
	log "github.com/sirupsen/logrus"

	"github.com/vul-dbgen/common"
	"github.com/vul-dbgen/updater"
)

const (
	minCount = 1000
)

var verRegexp = regexp.MustCompile(`^([0-9]+)(\.|\-)?([0-9a-zA-Z\-_.]*)`)

type ovalInfo struct {
	filename string
	feed     string
	version  int
}

var (
	ovals []ovalInfo = []ovalInfo{
		ovalInfo{"amazon/alas.rss.gz", "Amazon Linux", 1},
		ovalInfo{"amazon/alas2.rss.gz", "Amazon Linux 2", 2},
		// ovalInfo{"amazon/alas2022.rss.gz", "Amazon Linux 2022"},
	}
)

type rssFeed struct {
	Channel channel `xml:"channel"`
}

type channel struct {
	Title string `xml:"title"`
	Link  string `xml:"link"`
	Items []item `xml:"item"`
}

type item struct {
	Meta    string `xml:"title"`
	CVEs    string `xml:"description"`
	Issued  string `xml:"pubData"`
	LastMod string `xml:"lastBuildDate"`
	Guid    string `xml:"guid"`
	Link    string `xml:"link"`
}

type netMethod struct {
}

func (net netMethod) DownloadHTMLPage(url string) (string, string, error) {
	client := &http.Client{Timeout: 20 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	r, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer r.Body.Close()

	body, _ := ioutil.ReadAll(r.Body)
	plain := html2text.HTML2Text(string(body))
	return string(body), plain, nil
}

type AmazonFetcher struct {
	repositoryLocalPath string
}

func init() {
	updater.RegisterFetcher("amazon", &AmazonFetcher{})
}

func (u *AmazonFetcher) FetchUpdate() (resp updater.FetcherResponse, err error) {
	log.WithFields(log.Fields{"package": "Amazon"}).Info("fetching Amazon vulnerabilities")

	var nm netMethod
	for _, oval := range ovals {
		if vulns, err := u.fetchOvalFeed(&oval, &nm); err == nil {
			resp.Vulnerabilities = append(resp.Vulnerabilities, vulns...)
		}
	}

	if len(resp.Vulnerabilities) < minCount {
		log.WithFields(log.Fields{"count": len(resp.Vulnerabilities), "min": minCount}).Error("Amazon CVE count too small")
		return resp, fmt.Errorf("Amazon CVE count too small, %d < %d", len(resp.Vulnerabilities), minCount)
	}

	log.WithFields(log.Fields{"Vulnerabilities": len(resp.Vulnerabilities)}).Info("fetching amazon done")
	return resp, nil
}

func (u *AmazonFetcher) fetchOvalFeed(o *ovalInfo, net updater.NetInterface) ([]updater.Vulnerability, error) {
	log.WithFields(log.Fields{"file": o.filename}).Info("fetching Amazon oval feed")

	vulns := make([]updater.Vulnerability, 0)

	fullname := fmt.Sprintf("%s%s", updater.CVESourceRoot, o.filename)
	file, err := os.Open(fullname)
	if err != nil {
		log.WithFields(log.Fields{"file": o.filename}).Error("Failed to open the feed file")
		return vulns, fmt.Errorf("Unabled to fetch the oval feed")
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		log.WithFields(log.Fields{"file": o.filename}).Error("Failed to create feed reader")
		return vulns, fmt.Errorf("Unabled to fetch the oval feed")
	}
	defer gzr.Close()

	var rss rssFeed

	err = xml.NewDecoder(gzr).Decode(&rss)
	if err != nil {
		log.WithFields(log.Fields{"file": o.filename, "error": err}).Error("Failed to decode XML")
		return vulns, common.ErrCouldNotParse
	}

	for _, item := range rss.Channel.Items {
		tokens := strings.Split(item.Meta, " ")
		if len(tokens) < 3 {
			log.WithFields(log.Fields{"title": item.Meta}).Error("Failed to parse rss item title")
			continue
		}

		vuln := updater.Vulnerability{
			Name: tokens[0],
			Link: item.Link,
		}

		switch tokens[1] {
		case "(critical):":
			vuln.FeedRating = "Critical"
			vuln.Severity = common.Critical
		case "(important):":
			vuln.FeedRating = "Important"
			vuln.Severity = common.High
		case "(medium):":
			vuln.FeedRating = "Medium"
			vuln.Severity = common.Medium
		default:
			continue
		}

		cves := strings.Split(item.CVEs, " ")
		vuln.CVEs = make([]updater.CVE, len(cves))
		for i, cve := range cves {
			vuln.CVEs[i].Name = strings.TrimRight(cve, ",")
		}

		vuln.IssuedDate, _ = time.Parse(time.RFC1123, item.Issued)
		vuln.LastModDate, _ = time.Parse(time.RFC1123, item.LastMod)

		pkgs := make([]string, len(tokens)-2)
		for i, token := range tokens[2:] {
			pkgs[i] = strings.TrimRight(token, ",")
		}

		if desc, vers, err := getAlas(vuln.Name, vuln.Link, pkgs, net); err != nil {
			log.WithFields(log.Fields{"cve": vuln.Name, "error": err}).Error("Failed to parse amazon CVE page")
		} else if len(vers) == 0 {
			log.WithFields(log.Fields{"cve": vuln.Name, "pkgs": pkgs}).Error("Failed to parse amazon CVE page, no package version")
		} else {
			vuln.Description = strings.TrimSpace(desc)

			for pkg, pkgVer := range vers {
				ver, err := common.NewVersion(pkgVer)
				if err != nil {
					log.WithFields(log.Fields{"err": err, "version": pkgVer, "name": vuln.Name}).Error("invalid version")
					continue
				}
				featureVersion := updater.FeatureVersion{
					Feature: updater.Feature{
						Namespace: fmt.Sprintf("amzn:%d", o.version),
						Name:      pkg,
					},
					Version: ver,
				}
				// log.WithFields(log.Fields{"feature": featureVersion, "vuln": v.name, "link": vuln.Link}).Error("====================")

				vuln.FixedIn = append(vuln.FixedIn, featureVersion)
			}

			vulns = append(vulns, vuln)
		}
	}

	return vulns, nil
}

func (u *AmazonFetcher) Clean() {
}

func parseAlasPage(name, body, plain string, pkgs []string, net updater.NetInterface) (string, map[string]string, error) {
	var description string
	if a := strings.Index(plain, "Issue Overview:"); a > 0 {
		if b := strings.Index(plain, "Affected Packages:"); b > 0 {
			description = strings.TrimSpace(plain[a+15 : b])
		}
	}

	pkgVers := make(map[string]string)

	// use original body instead of plain
	if a := strings.Index(body, "New Packages:</b><pre>"); a > 0 {
		plain = body[a+22:]
		if a = strings.Index(plain, "</pre>"); a > 0 {
			plain = plain[:a]
		}
		plain = strings.ReplaceAll(plain, "<br />", " ")
		plain = strings.ReplaceAll(plain, "&nbsp;", " ")

		strs := strings.Split(plain, " ")
		var arch string
		for _, str := range strs {
			str = strings.TrimSpace(str)
			if strings.HasSuffix(str, ":") {
				arch = fmt.Sprintf(".%s", str[:len(str)-1])
			} else if arch != "" {
				if s := strings.Index(str, arch); s > 0 {
					for _, pkg := range pkgs {
						if strings.HasPrefix(str, pkg) {
							version := str[len(pkg)+1 : s]
							if verRegexp.MatchString(version) {
								pkgVers[pkg] = version
							}
						}
					}
					if len(pkgVers) == len(pkgs) {
						return description, pkgVers, nil
					}
				}
			}
		}
	}

	return description, pkgVers, nil
}

func getAlas(name, link string, pkgs []string, net updater.NetInterface) (string, map[string]string, error) {
	body, plain, err := net.DownloadHTMLPage(link)
	if err != nil {
		return "", nil, err
	}

	return parseAlasPage(name, body, plain, pkgs, net)
}
