package apps

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/vul-dbgen/common"
)

const appManualFolder = "app-manual/"

func manualUpdate() error {

	/*
		modVul := common.AppModuleVul{
			VulName:     "CVE-2020-1938",
			AppName:     "Tomcat",
			ModuleName:  "Tomcat",
			Description: "When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.",
			Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-1938",
			Score:       7.5,
			Severity:    common.High,
			AffectedVer: []common.AppModuleVersion{
				common.AppModuleVersion{OpCode: "gteq", Version: "1.0"},
				common.AppModuleVersion{OpCode: "andlteq", Version: "6.9.99"},
				common.AppModuleVersion{OpCode: "orlt", Version: "7.0.100,7.0"},
				common.AppModuleVersion{OpCode: "orlt", Version: "8.5.51,8.5"},
				common.AppModuleVersion{OpCode: "orlt", Version: "9.0.31,9.0"},
			},
			FixedVer: []common.AppModuleVersion{
				common.AppModuleVersion{OpCode: "gteq", Version: "7.0.100,7.0"},
				common.AppModuleVersion{OpCode: "orgteq", Version: "8.5.51,8.5"},
				common.AppModuleVersion{OpCode: "orgteq", Version: "9.0.31,9.0"},
			},
		}
		modVul.CVEs = []string{modVul.VulName}
		addAppVulMap(&modVul)
	*/

	var cveCount int

	for _, fn := range []string{
		fmt.Sprintf("%s%s%s", common.CVESourceRoot, appManualFolder, "busybox.db"),
		fmt.Sprintf("%s%s%s", common.CVESourceRoot, appManualFolder, "toomcat.db"),
	} {
		file, err := os.Open(fn)
		if err != nil {
			continue
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			var v common.AppModuleVul
			if err = json.Unmarshal(scanner.Bytes(), &v); err == nil {
				addAppVulMap(&v)
				cveCount++
			}
		}
	}

	if cveCount == 0 {
		log.WithFields(log.Fields{"module": "manual"}).Error("Failed to read any CVE")
		return fmt.Errorf("Failed to read any CVE")
	} else {
		log.WithFields(log.Fields{"module": "manual", "count": cveCount}).Info()
		return nil
	}
}
