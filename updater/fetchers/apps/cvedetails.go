package apps

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/vul-dbgen/common"
)

const (
	cvedetailURL                = "https://www.cvedetails.com"
	busyboxCVEDetailURL         = "https://www.cvedetails.com/vulnerability-list/vendor_id-4282/Busybox.html"
	jacksonDatabindCVEDetailURL = "https://www.cvedetails.com/vulnerability-list/vendor_id-15866/product_id-42991/Fasterxml-Jackson-databind.html"
	wordpressCVEDetailURL       = "https://www.cvedetails.com/vulnerability-list/vendor_id-2337/Wordpress.html"
	tomcatCVEDetailURL          = "https://www.cvedetails.com/vulnerability-list/vendor_id-45/product_id-887/"
	dotnetCoreCVEDetailURL      = "https://www.cvedetails.com/vulnerability-list/vendor_id-26/product_id-43007/Microsoft-.net-Core.html"
	dotnetFrameworkCVEDetailURL = "https://www.cvedetails.com/vulnerability-list/vendor_id-26/product_id-2002/Microsoft-.net-Framework.html"
)

func cvedetailUpdate() error {
	var err error

	if err = dotnetUpdate(); err != nil {
		return err
	}
	if err = busyboxUpdate(); err != nil {
		return err
	}
	// if err = jacksonDatabindUpdate(); err != nil {
	// 	return err
	// }
	if err = tomcatUpdate(); err != nil {
		return err
	}
	if err = wordpressUpdate(); err != nil {
		return err
	}
	return nil
}

func busyboxUpdate() error {
	return readCVEDetailsPage(busyboxCVEDetailURL, "Busybox", "busybox")
}

func dotnetUpdate() error {
	if err := readCVEDetailsPage(dotnetCoreCVEDetailURL, ".net Core", ".NET:Core"); err != nil {
		return err
	}
	return readCVEDetailsPage(dotnetFrameworkCVEDetailURL, ".net Framework", ".NET:Framework")
}

func jacksonDatabindUpdate() error {
	return readCVEDetailsPage(jacksonDatabindCVEDetailURL, "jackson-databind", "com.fasterxml.jackson.core.jackson-core")
}

func tomcatUpdate() error {
	return readCVEDetailsPage(tomcatCVEDetailURL, "Tomcat", "Tomcat")
}

func wordpressUpdate() error {
	return readCVEDetailsPage(wordpressCVEDetailURL, "Wordpress", "Wordpress")
}

func readCVEDetailsPage(url, product, module string) error {
	log.WithFields(log.Fields{"url": url, "product": product, "moduel": module}).Info("fetching vulnerabilities")

	var cveUrlRegexp = regexp.MustCompile(`<td nowrap><a href="([\/a-zA-Z0-9\-]*)"\s*title="([CVE\-0-9]*)\s+security vulnerability details">([CVE\-0-9]*)</a></td>`)
	var cveCount int

	r, err := http.Get(url)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "url": url}).Error("Failed to download cve page")
		return err
	}
	defer r.Body.Close()
	body, _ := ioutil.ReadAll(r.Body)

	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		line := scanner.Text()
		match := cveUrlRegexp.FindAllStringSubmatch(line, 1)
		if len(match) > 0 {
			s := match[0]
			cveurl := s[1]
			cve := s[2]
			if vul, err := getCveDetail(cvedetailURL+cveurl, cve, product, module); err == nil && vul != nil {
				// log.WithFields(log.Fields{"cve": vul}).Info()
				addAppVulMap(vul)
				cveCount++
			}
		} else {
			continue
		}
	}

	if cveCount == 0 {
		log.WithFields(log.Fields{"module": module}).Error("Failed to read any CVE")
		return fmt.Errorf("Failed to read any CVE")
	} else {
		log.WithFields(log.Fields{"module": module, "count": cveCount}).Info()
		return nil
	}
}

func getCveDetail(cveurl, cve, product, module string) (*common.AppModuleVul, error) {
	var descriptRegexp = regexp.MustCompile(`<meta name="description" content="CVE-[0-9]*-[0-9]* : (.*)"/>`)
	var scoreRegexp = regexp.MustCompile(`<td><div class="cvssbox" style="background-color:#[a-z0-9]*">([0-9\.]*)</div></td>`)
	var affectedVerRegexp = regexp.MustCompile(`\s*([0-9\.]*)\s*</td>`)
	var affectedUpdateRegexp = regexp.MustCompile(`\s*([A-Za-z0-9\.]*)\s*</td>`)

	var modVul common.AppModuleVul
	r, err := http.Get(cveurl)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "url": cveurl}).Error("Failed to download cve detail")
		return nil, err
	}

	body, _ := ioutil.ReadAll(r.Body)
	defer r.Body.Close()

	scanner := bufio.NewScanner(strings.NewReader(string(body)))

	var gettingFfixedVer, productsAffectedBy bool
	var affectedStatus int
	var affectedVersion string
	var productMatch bool

	for scanner.Scan() {
		line := scanner.Text()
		if modVul.Description == "" {
			match := descriptRegexp.FindAllStringSubmatch(line, 1)
			if len(match) > 0 {
				s := match[0]
				modVul.Description = s[1]
			}
		}
		if modVul.Score == 0 {
			match := scoreRegexp.FindAllStringSubmatch(line, 1)
			if len(match) > 0 {
				s := match[0]
				if fl, err := strconv.ParseFloat(s[1], 64); err == nil {
					modVul.Score = fl
				}
			}
		}

		if strings.Contains(line, "Products Affected By "+cve) {
			productsAffectedBy = true
		} else if strings.Contains(line, "Number Of Affected Versions By Product") {
			productsAffectedBy = false
		}
		if productsAffectedBy && strings.Contains(line, "<td class=\"num\">") {
			gettingFfixedVer = true
			affectedStatus = 0
		}
		if gettingFfixedVer {
			if affectedStatus == 7 {
				//product
				if strings.Contains(line, fmt.Sprintf(">%s</a>", product)) {
					productMatch = true
				} else {
					productMatch = false
				}
			} else if productMatch && affectedStatus == 9 {
				//affectedVersion
				match := affectedVerRegexp.FindAllStringSubmatch(line, 1)
				if len(match) > 0 && len(match[0]) > 1 && len(match[0][1]) > 0 {
					affectedVersion = match[0][1]
				}
			} else if productMatch && affectedVersion != "" && affectedStatus == 11 {
				//affectedVersion update
				match := affectedUpdateRegexp.FindAllStringSubmatch(line, 1)
				if len(match) > 0 && len(match[0]) > 1 && len(match[0][1]) > 0 {
					afv := common.AppModuleVersion{OpCode: "", Version: affectedVersion + "." + match[0][1]}
					modVul.AffectedVer = append(modVul.AffectedVer, afv)
				} else {
					afv := common.AppModuleVersion{OpCode: "", Version: affectedVersion}
					modVul.AffectedVer = append(modVul.AffectedVer, afv)
				}
			}
			affectedStatus++
		}
	}

	//calibrate the cve affected version
	if m, ok := cveCalibrate[cve]; ok {
		log.WithFields(log.Fields{"cve": cve, "afv": m}).Info("Calibration")
		modVul.AffectedVer = append(modVul.AffectedVer, m...)
	}

	modVul.VulName = cve
	modVul.AppName = product
	modVul.ModuleName = module
	modVul.Link = cveurl
	modVul.CVEs = []string{cve}

	// if cve == "CVE-2021-31204" {
	// 	log.WithFields(log.Fields{"mv": modVul}).Error("====================")
	// }

	return &modVul, nil
}
