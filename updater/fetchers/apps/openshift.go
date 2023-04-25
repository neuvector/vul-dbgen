package apps

import (
	"github.com/vul-dbgen/common"
)

// add kubernetes vulnerability manually
func openshiftUpdate() error {
	modVul := common.AppModuleVul{
		VulName:     "CVE-2018-1002105",
		AppName:     "openshift.kubernetes",
		ModuleName:  "openshift.kubernetes",
		Description: "A flaw has been detected in kubernetes which allows privilege escalation and access to sensitive information in OpenShift products and services.  This issue has been assigned CVE-2018-1002105 and has a security impact of Critical.",
		Link:        "https://access.redhat.com/security/vulnerabilities/3716411",
		Score:       9.8,
		Severity:    "High",
		AffectedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "lt", Version: "3.2.1.34-2,3.2"},
			common.AppModuleVersion{OpCode: "orlt", Version: "3.11.43-1,3.11"},
			common.AppModuleVersion{OpCode: "orlt", Version: "3.10.72-1,3.10"},
			common.AppModuleVersion{OpCode: "orlt", Version: "3.9.51-1,3.9"},
			common.AppModuleVersion{OpCode: "orlt", Version: "3.8.44-1,3.8"},
			common.AppModuleVersion{OpCode: "orlt", Version: "3.7.72-1,3.7"},
			common.AppModuleVersion{OpCode: "orlt", Version: "3.6.173.0.140-1,3.6"},
			common.AppModuleVersion{OpCode: "orlt", Version: "3.5.5.31.80-1,3.5"},
			common.AppModuleVersion{OpCode: "orlt", Version: "3.4.1.44.57-1,3.4"},
			common.AppModuleVersion{OpCode: "orlt", Version: "3.3.1.46.45-1,3.3"},
		},
		FixedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gteq", Version: "3.2.1.34-2,3.2"},
			common.AppModuleVersion{OpCode: "orgteq", Version: "3.11.43-1,3.11"},
			common.AppModuleVersion{OpCode: "orgteq", Version: "3.10.72-1,3.10"},
			common.AppModuleVersion{OpCode: "orgteq", Version: "3.9.51-1,3.9"},
			common.AppModuleVersion{OpCode: "orgteq", Version: "3.8.44-1,3.8"},
			common.AppModuleVersion{OpCode: "orgteq", Version: "3.7.72-1,3.7"},
			common.AppModuleVersion{OpCode: "orgteq", Version: "3.6.173.0.140-1,3.6"},
			common.AppModuleVersion{OpCode: "orgteq", Version: "3.5.5.31.80-1,3.5"},
			common.AppModuleVersion{OpCode: "orgteq", Version: "3.4.1.44.57-1,3.4"},
			common.AppModuleVersion{OpCode: "orgteq", Version: "3.3.1.46.45-1,3.3"},
		},
	}
	modVul.CVEs = []string{modVul.VulName}
	addAppVulMap(&modVul)

	// 2019-1002101
	modVul = common.AppModuleVul{
		VulName:     "CVE-2019-1002101",
		AppName:     "openshift.kubernetes",
		ModuleName:  "openshift.kubernetes",
		Description: "A flaw was found in Kubernetes via the mishandling of symlinks when copying files from a running container. An attacker could exploit this by convincing a user to use `kubectl cp` or `oc cp` with a malicious container, allowing for arbitrary files to be overwritten on the host machine.",
		Link:        "https://access.redhat.com/security/cve/cve-2019-1002101",
		Score:       5.3,
		Severity:    "Medium",
		AffectedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "lt", Version: "3.11.99,3.11"},
			common.AppModuleVersion{OpCode: "orlt", Version: "3.10.99,3.10"},
			common.AppModuleVersion{OpCode: "orlt", Version: "3.9.99,3.9"},
		},
	}
	modVul.CVEs = []string{modVul.VulName}
	addAppVulMap(&modVul)

	// CVE-2021-25735
	modVul = common.AppModuleVul{
		VulName:     "CVE-2021-25735",
		AppName:     "openshift.kubernetes",
		ModuleName:  "openshift.kubernetes",
		Description: "A security issue was discovered in kube-apiserver that could allow node updates to bypass a Validating Admission Webhook. You are only affected by this vulnerability if you run a Validating Admission Webhook for Nodes that denies admission based at least partially on the old state of the Node object.",
		ScoreV3:     6.5,
		VectorsV3:   "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H",
		Severity:    "Medium",
		AffectedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gteq", Version: "1.0"},
			common.AppModuleVersion{OpCode: "andlteq", Version: "1.18.17"},
			common.AppModuleVersion{OpCode: "orlteq", Version: "1.19.9,1.19"},
			common.AppModuleVersion{OpCode: "orlteq", Version: "1.20.5,1.20"},
		},
		FixedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gt", Version: "1.19.9,1.19"},
			common.AppModuleVersion{OpCode: "orgt", Version: "1.20.5,1.20"},
		},
	}
	modVul.CVEs = []string{modVul.VulName}
	addAppVulMap(&modVul)

	// CVE-2021-25741
	modVul = common.AppModuleVul{
		VulName:     "CVE-2021-25741",
		AppName:     "openshift.kubernetes",
		ModuleName:  "openshift.kubernetes",
		Description: "A security issue was discovered in Kubernetes where a user may be able to create a container with subpath volume mounts to access files & directories outside of the volume, including on the host filesystem.",
		ScoreV3:     8.8,
		VectorsV3:   "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
		Severity:    "High",
		AffectedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gteq", Version: "1.0"},
			common.AppModuleVersion{OpCode: "andlteq", Version: "1.19.14"},
			common.AppModuleVersion{OpCode: "orlteq", Version: "1.20.10,1.20"},
			common.AppModuleVersion{OpCode: "orlteq", Version: "1.21.4,1.21"},
			common.AppModuleVersion{OpCode: "orlteq", Version: "1.22.1,1.22"},
		},
		FixedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gt", Version: "1.19.14,1.19"},
			common.AppModuleVersion{OpCode: "orgt", Version: "1.20.10,1.20"},
			common.AppModuleVersion{OpCode: "orgt", Version: "1.21.4,1.21"},
			common.AppModuleVersion{OpCode: "orgt", Version: "1.22.1,1.22"},
		},
	}
	modVul.CVEs = []string{modVul.VulName}
	addAppVulMap(&modVul)

	// CVE-2020-8554
	modVul = common.AppModuleVul{
		VulName:     "CVE-2020-8554",
		AppName:     "openshift.kubernetes",
		ModuleName:  "kubernetes",
		Description: "Kubernetes API server in all versions allow an attacker who is able to create a ClusterIP service and set the spec.externalIPs field, to intercept traffic to that IP address. Additionally, an attacker who is able to patch the status (which is considered a privileged operation and should not typically be granted to users) of a LoadBalancer service can set the status.loadBalancer.ingress.ip to similar effect.",
		ScoreV3:     5.0,
		Score:       6.0,
		VectorsV3:   "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
		Vectors:     "AV:N/AC:M/Au:S/C:P/I:P/A:P",
		Severity:    "Medium",
		AffectedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gteq", Version: "1.0"},
			common.AppModuleVersion{OpCode: "andlteq", Version: "1.22.0"},
		},
		FixedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gt", Version: "1.22.0"},
		},
	}
	modVul.CVEs = []string{modVul.VulName}
	addAppVulMap(&modVul)

	return nil
}
