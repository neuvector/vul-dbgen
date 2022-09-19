package apps

import (
	"github.com/vul-dbgen/common"
)

func manualUpdate() error {
	modVul := common.AppModuleVul{
		VulName:     "CVE-2020-1938",
		ModuleName:  "Tomcat",
		Description: "When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.",
		Link:        "https://nvd.nist.gov/vuln/detail/CVE-2020-1938",
		Score:       7.5,
		Severity:    "High",
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

	// Keep the following log4j related cves until 4.4.2, because in 4.4.1
	// enforcer report module name as org.apache.logging.log4j.log4j; in 4.4.2,
	// it will report as org.apache.logging.log4j:log4j-core. Github advisory
	// does't report on module org.apache.logging.log4j.log4j for these cves
	modVul = common.AppModuleVul{
		VulName:     "CVE-2021-44228",
		ModuleName:  "org.apache.logging.log4j.log4j",
		Description: "Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. In previous releases (>2.10) this behavior can be mitigated by setting system property 'log4j2.formatMsgNoLookups' to 'true' or it can be mitigated in prior releases (<2.10) by removing the JndiLookup class from the classpath (example: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class).",
		Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
		Score:       9.3,
		Vectors:     "AV:N/AC:M/Au:N/C:C/I:C/A:C",
		ScoreV3:     10.0,
		VectorsV3:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
		Severity:    "High",
		AffectedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gteq", Version: "2.0"},
			common.AppModuleVersion{OpCode: "andlteq", Version: "2.14.1"},
		},
		FixedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "lt", Version: "2.0"},
			common.AppModuleVersion{OpCode: "orgteq", Version: "2.15"},
		},
	}
	modVul.CVEs = []string{modVul.VulName}
	addAppVulMap(&modVul)

	modVul = common.AppModuleVul{
		VulName:     "CVE-2021-45046",
		ModuleName:  "org.apache.logging.log4j.log4j",
		Description: "It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in a denial of service (DOS) attack. Log4j 2.15.0 makes a best-effort attempt to restrict JNDI LDAP lookups to localhost by default. Log4j 2.16.0 fixes this issue by removing support for message lookup patterns and disabling JNDI functionality by default.",
		Link:        "https://nvd.nist.gov/vuln/detail/CVE-2021-45046",
		Score:       9.0,
		Vectors:     "AV:N/AC:H/Au:N/C:N/I:N/A:P",
		ScoreV3:     9.0,
		VectorsV3:   "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
		Severity:    "High",
		AffectedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gteq", Version: "2.14.1"},
			common.AppModuleVersion{OpCode: "andlteq", Version: "2.15.0"},
		},
		FixedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "lt", Version: "2.15"},
			common.AppModuleVersion{OpCode: "orgteq", Version: "2.16"},
		},
	}
	modVul.CVEs = []string{modVul.VulName}
	addAppVulMap(&modVul)

	return nil
}
