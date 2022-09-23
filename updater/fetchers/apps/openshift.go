package apps

import (
	"github.com/vul-dbgen/common"
)

// add kubernetes vulnerability manually
/*
func kubernetesUpdate() error {
	modVul := common.AppModuleVul{
		VulName:     "CVE-2018-1002105",
		ModuleName:  "kubernetes",
		Description: "A privilege escalation vulnerability exists in OpenShift Container Platform which allows for compromise of pods running co-located on a compute node. This access could include access to all secrets, pods, environment variables, running pod/container processes, and persistent volumes, including in privileged containers",
		Link:        "https://nvd.nist.gov/vuln/detail/CVE-2018-1002105",
		Score:       9.8,
		Severity:    "High",
		AffectedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gteq", Version: "1.0"},
			common.AppModuleVersion{OpCode: "andlteq", Version: "1.9.99"},
			common.AppModuleVersion{OpCode: "orlt", Version: "1.10.11,1.10"},
			common.AppModuleVersion{OpCode: "orlt", Version: "1.11.5,1.11"},
			common.AppModuleVersion{OpCode: "orlt", Version: "1.12.3,1.12"},
		},
		FixedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gteq", Version: "1.10.11,1.10"},
			common.AppModuleVersion{OpCode: "orgteq", Version: "1.11.5,1.11"},
			common.AppModuleVersion{OpCode: "orgteq", Version: "1.12.3,1.12"},
		},
	}
	modVul.CVEs = []string{modVul.VulName}
	addAppVulMap(&modVul)

	// --
	modVul = common.AppModuleVul{
		VulName:     "CVE-2019-1002100",
		ModuleName:  "kubernetes",
		Description: "Users that are authorized to make patch requests to the Kubernetes API Server can send a specially crafted patch of type “json-patch” (e.g. kubectl patch --type json or \"Content-Type: application/json-patch+json\") that consumes excessive resources while processing, causing a Denial of Service on the API Server.",
		Link:        "https://github.com/kubernetes/kubernetes/issues/74534",
		Score:       6.5,
		Severity:    "Medium",
		AffectedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gteq", Version: "1.0"},
			common.AppModuleVersion{OpCode: "andlteq", Version: "1.10.99"},
			common.AppModuleVersion{OpCode: "orlt", Version: "1.11.8,1.11"},
			common.AppModuleVersion{OpCode: "orlt", Version: "1.12.6,1.12"},
			common.AppModuleVersion{OpCode: "orlt", Version: "1.13.4,1.13"},
		},
		FixedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gteq", Version: "1.11.8,1.11"},
			common.AppModuleVersion{OpCode: "orgteq", Version: "1.12.6,1.12"},
			common.AppModuleVersion{OpCode: "orgteq", Version: "1.13.4,1.13"},
		},
	}
	modVul.CVEs = []string{modVul.VulName}
	addAppVulMap(&modVul)

	// --
	modVul = common.AppModuleVul{
		VulName:     "CVE-2019-1002101",
		ModuleName:  "kubernetes",
		Description: "The kubectl cp command allows copying files between containers and the user machine. To copy files from a container, Kubernetes creates a tar inside the container, copies it over the network, and kubectl unpacks it on the user?s machine. If the tar binary in the container is malicious, it could run any code and output unexpected, malicious results. An attacker could use this to write files to any path on the user?s machine when kubectl cp is called, limited only by the system permissions of the local user. The untar function can both create and follow symbolic links. The issue is resolved in kubectl v1.11.9, v1.12.7, v1.13.5, and v1.14.0.",
		Link:        "https://nvd.nist.gov/vuln/detail/CVE-2019-1002101",
		Score:       5.3,
		Severity:    "Medium",
		AffectedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "lt", Version: "1.11.9,1.11"},
			common.AppModuleVersion{OpCode: "orlt", Version: "1.12.7,1.12"},
			common.AppModuleVersion{OpCode: "orlt", Version: "1.13.5,1.13"},
		},
		FixedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gteq", Version: "1.11.9,1.11"},
			common.AppModuleVersion{OpCode: "orgteq", Version: "1.12.7,1.12"},
			common.AppModuleVersion{OpCode: "orgteq", Version: "1.13.5,1.13"},
			common.AppModuleVersion{OpCode: "orgteq", Version: "1.14.0,1.14"},
		},
	}
	modVul.CVEs = []string{modVul.VulName}
	addAppVulMap(&modVul)

	// --
	modVul = common.AppModuleVul{
		VulName:     "CVE-2019-11247",
		ModuleName:  "kubernetes",
		Description: "API server allows access to custom resources via wrong scope.\nThis vulnerability allows access to a cluster-scoped custom resource if the request is made as if the resource were namespaced. Authorizations for the resource accessed in this manner are enforced using roles and role bindings within the namespace, meaning that a user with access only to a resource in one namespace could create, view update or delete the cluster-scoped resource (according to their namespace role privileges).",
		Link:        "https://seclists.org/oss-sec/2019/q3/117",
		Score:       8,
		Severity:    "High",
		AffectedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gteq", Version: "1.0"},
			common.AppModuleVersion{OpCode: "andlteq", Version: "1.12.99"},
			common.AppModuleVersion{OpCode: "orlt", Version: "1.13.9,1.13"},
			common.AppModuleVersion{OpCode: "orlt", Version: "1.14.5,1.14"},
			common.AppModuleVersion{OpCode: "orlt", Version: "1.15.2,1.15"},
		},
		FixedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gteq", Version: "1.13.9,1.13"},
			common.AppModuleVersion{OpCode: "orgteq", Version: "1.14.5,1.14"},
			common.AppModuleVersion{OpCode: "orgteq", Version: "1.15.2,1.15"},
		},
	}
	modVul.CVEs = []string{modVul.VulName}
	addAppVulMap(&modVul)

	// --
	modVul = common.AppModuleVul{
		VulName:     "CVE-2019-11249",
		ModuleName:  "kubernetes",
		Description: "Incomplete fixes for CVE-2019-1002101 and CVE-2019-11246,kubectl cp potential directory traversal.\nThis vulnerability allows a malicious container to cause a file to be created or replaced on the client computer when the client uses the kubectl cp operation. The vulnerability is a client-side defect and requires user interaction to be exploited.",
		Link:        "https://github.com/kubernetes/kubernetes/issues/80984",
		Score:       8,
		Severity:    "High",
		AffectedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gteq", Version: "1.0"},
			common.AppModuleVersion{OpCode: "andlteq", Version: "1.12.99"},
			common.AppModuleVersion{OpCode: "orlt", Version: "1.13.9,1.13"},
			common.AppModuleVersion{OpCode: "orlt", Version: "1.14.5,1.14"},
			common.AppModuleVersion{OpCode: "orlt", Version: "1.15.2,1.15"},
		},
		FixedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gteq", Version: "1.13.9,1.13"},
			common.AppModuleVersion{OpCode: "orgteq", Version: "1.14.5,1.14"},
			common.AppModuleVersion{OpCode: "orgteq", Version: "1.15.2,1.15"},
		},
	}
	modVul.CVEs = []string{modVul.VulName}
	addAppVulMap(&modVul)

	// --
	modVul = common.AppModuleVul{
		VulName:     "CVE-2019-9512",
		ModuleName:  "kubernetes",
		Description: "Some HTTP/2 implementations are vulnerable to ping floods, potentially leading to a denial of service. The attacker sends continual pings to an HTTP/2 peer, causing the peer to build an internal queue of responses. Depending on how efficiently this data is queued, this can consume excess CPU, memory, or both.",
		Link:        "https://groups.google.com/forum/#!topic/kubernetes-security-announce/wlHLHit1BqA",
		Score:       7.5,
		Severity:    "High",
		AffectedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gteq", Version: "1.0"},
			common.AppModuleVersion{OpCode: "andlteq", Version: "1.12.99"},
			common.AppModuleVersion{OpCode: "orlt", Version: "1.13.10,1.13"},
			common.AppModuleVersion{OpCode: "orlt", Version: "1.14.6,1.14"},
			common.AppModuleVersion{OpCode: "orlt", Version: "1.15.3,1.15"},
		},
		FixedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gteq", Version: "1.13.10,1.13"},
			common.AppModuleVersion{OpCode: "orgteq", Version: "1.14.6,1.14"},
			common.AppModuleVersion{OpCode: "orgteq", Version: "1.15.3,1.15"},
		},
	}
	modVul.CVEs = []string{modVul.VulName}
	addAppVulMap(&modVul)

	modVul.VulName = "CVE-2019-9514"
	modVul.CVEs = []string{modVul.VulName}
	addAppVulMap(&modVul)

	// --
	modVul = common.AppModuleVul{
		VulName:     "CVE-2019-11253",
		ModuleName:  "kubernetes",
		Description: "Improper input validation in the Kubernetes API server in versions v1.0-1.12 and versions prior to v1.13.12, v1.14.8, v1.15.5, and v1.16.2 allows authorized users to send malicious YAML or JSON payloads, causing the API server to consume excessive CPU or memory, potentially crashing and becoming unavailable. Prior to v1.14.0, default RBAC policy authorized anonymous users to submit requests that could trigger this vulnerability. Clusters upgraded from a version prior to v1.14.0 keep the more permissive policy by default for backwards compatibility.",
		Score:       7.5,
		Severity:    "High",
		AffectedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gteq", Version: "1.0"},
			common.AppModuleVersion{OpCode: "andlteq", Version: "1.12.99"},
			common.AppModuleVersion{OpCode: "orlt", Version: "1.13.12,1.13"},
			common.AppModuleVersion{OpCode: "orlt", Version: "1.14.8,1.14"},
			common.AppModuleVersion{OpCode: "orlt", Version: "1.15.5,1.15"},
			common.AppModuleVersion{OpCode: "orlt", Version: "1.16.2,1.16"},
		},
		FixedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gteq", Version: "1.13.12,1.13"},
			common.AppModuleVersion{OpCode: "orgteq", Version: "1.14.8,1.14"},
			common.AppModuleVersion{OpCode: "orgteq", Version: "1.15.5,1.15"},
			common.AppModuleVersion{OpCode: "orgteq", Version: "1.16.2,1.16"},
		},
	}
	modVul.CVEs = []string{modVul.VulName}
	addAppVulMap(&modVul)

	modVul.VulName = "CVE-2019-16276"
	modVul.CVEs = []string{modVul.VulName}
	addAppVulMap(&modVul)

	// CVE-2020-8552
	modVul = common.AppModuleVul{
		VulName:     "CVE-2020-8552",
		ModuleName:  "kubernetes",
		Description: "The Kubernetes API server component in versions prior to 1.15.9, 1.16.0-1.16.6, and 1.17.0-1.17.2 has been found to be vulnerable to a denial of service attack via successful API requests.",
		Score:       7.5,
		Severity:    "High",
		AffectedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gteq", Version: "1.0"},
			common.AppModuleVersion{OpCode: "andlteq", Version: "1.15.10"},
			common.AppModuleVersion{OpCode: "orlteq", Version: "1.16.6,1.16"},
			common.AppModuleVersion{OpCode: "orlteq", Version: "1.17.2,1.17"},
		},
		FixedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gt", Version: "1.15.10,1.15"},
			common.AppModuleVersion{OpCode: "orgt", Version: "1.16.6,1.16"},
			common.AppModuleVersion{OpCode: "orgt", Version: "1.17.2,1.17"},
		},
	}
	modVul.CVEs = []string{modVul.VulName}
	addAppVulMap(&modVul)

	// CVE-2020-8555
	modVul = common.AppModuleVul{
		VulName:     "CVE-2020-8555",
		ModuleName:  "kubernetes",
		Description: "A server side request forgery (SSRF) flaw was found in Kubernetes. The kube-controller-manager allows authorized users with the ability to create StorageClasses or certain Volume types to leak up to 500 bytes of arbitrary information from the master's host network. This can include secrets from the kube-apiserver through the unauthenticated localhost port (if enabled).",
		Score:       6.3,
		Severity:    "Medium",
		AffectedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gteq", Version: "1.0"},
			common.AppModuleVersion{OpCode: "andlteq", Version: "1.15.11"},
			common.AppModuleVersion{OpCode: "orlteq", Version: "1.16.8,1.16"},
			common.AppModuleVersion{OpCode: "orlteq", Version: "1.17.4,1.17"},
			common.AppModuleVersion{OpCode: "orlteq", Version: "1.18.0,1.18"},
		},
		FixedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gt", Version: "1.15.11,1.15"},
			common.AppModuleVersion{OpCode: "orgt", Version: "1.16.8,1.16"},
			common.AppModuleVersion{OpCode: "orgt", Version: "1.17.4,1.17"},
			common.AppModuleVersion{OpCode: "orgt", Version: "1.18.0,1.18"},
		},
	}
	modVul.CVEs = []string{modVul.VulName}
	addAppVulMap(&modVul)

	// CVE-2020-8558
	modVul = common.AppModuleVul{
		VulName:     "CVE-2020-8558",
		ModuleName:  "kubernetes",
		Description: "The Kubelet and kube-proxy components in versions 1.1.0-1.16.10, 1.17.0-1.17.6, and 1.18.0-1.18.3 were found to contain a security issue which allows adjacent hosts to reach TCP and UDP services bound to 127.0.0.1 running on the node or in the node's network namespace. Such a service is generally thought to be reachable only by other processes on the same host, but due to this defeect, could be reachable by other hosts on the same LAN as the node, or by containers running on the same node as the service.",
		Score:       5.8,
		Severity:    "Medium",
		AffectedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gteq", Version: "1.1.0"},
			common.AppModuleVersion{OpCode: "andlteq", Version: "1.16.10"},
			common.AppModuleVersion{OpCode: "orlteq", Version: "1.17.6,1.17"},
			common.AppModuleVersion{OpCode: "orlteq", Version: "1.18.3,1.18"},
		},
		FixedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gt", Version: "1.16.10,1.16"},
			common.AppModuleVersion{OpCode: "orgt", Version: "1.17.6,1.17"},
			common.AppModuleVersion{OpCode: "orgt", Version: "1.18.3,1.18"},
		},
	}
	modVul.CVEs = []string{modVul.VulName}
	addAppVulMap(&modVul)

	// CVE-2020-8559
	modVul = common.AppModuleVul{
		VulName:     "CVE-2020-8559",
		ModuleName:  "kubernetes",
		Description: "The Kubernetes kube-apiserver in versions v1.6-v1.15, and versions prior to v1.16.13, v1.17.9 and v1.18.6 are vulnerable to an unvalidated redirect on proxied upgrade requests that could allow an attacker to escalate privileges from a node compromise to a full cluster compromise.",
		Score:       6.0,
		Severity:    "Medium",
		AffectedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gteq", Version: "1.6"},
			common.AppModuleVersion{OpCode: "andlteq", Version: "1.16"},
			common.AppModuleVersion{OpCode: "orlteq", Version: "1.16.12,1.16"},
			common.AppModuleVersion{OpCode: "orlteq", Version: "1.17.8,1.17"},
			common.AppModuleVersion{OpCode: "orlteq", Version: "1.18.5,1.18"},
		},
		FixedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gt", Version: "1.16.12,1.16"},
			common.AppModuleVersion{OpCode: "orgt", Version: "1.17.8,1.17"},
			common.AppModuleVersion{OpCode: "orgt", Version: "1.18.5,1.18"},
		},
	}
	modVul.CVEs = []string{modVul.VulName}
	addAppVulMap(&modVul)

	// CVE-2020-10749
	modVul = common.AppModuleVul{
		VulName:     "CVE-2020-10749",
		ModuleName:  "kubernetes",
		Description: "A cluster configured to use an affected container networking implementation is susceptible to man-in-the-middle (MitM) attacks. By sending “rogue” router advertisements, a malicious container can reconfigure the host to redirect part or all of the IPv6 traffic of the host to the attacker-controlled container. Even if there was no IPv6 traffic before, if the DNS returns A (IPv4) and AAAA (IPv6) records, many HTTP libraries will try to connect via IPv6 first then fallback to IPv4, giving an opportunity to the attacker to respond.",
		Score:       6.0,
		Vectors:     "AV:N/AC:M/Au:S/C:P/I:P/A:P",
		ScoreV3:     6.0,
		VectorsV3:   "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:L",
		Severity:    "Medium",
		AffectedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gteq", Version: "1.0"},
			common.AppModuleVersion{OpCode: "andlteq", Version: "1.16.11"},
			common.AppModuleVersion{OpCode: "orlteq", Version: "1.17.6,1.17"},
			common.AppModuleVersion{OpCode: "orlteq", Version: "1.18.3,1.18"},
		},
		FixedVer: []common.AppModuleVersion{
			common.AppModuleVersion{OpCode: "gt", Version: "1.16.11,1.16"},
			common.AppModuleVersion{OpCode: "orgt", Version: "1.17.6,1.17"},
			common.AppModuleVersion{OpCode: "orgt", Version: "1.18.3,1.18"},
		},
	}
	modVul.CVEs = []string{modVul.VulName}
	addAppVulMap(&modVul)

	// CVE-2021-25735
	modVul = common.AppModuleVul{
		VulName:     "CVE-2021-25735",
		ModuleName:  "kubernetes",
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
		ModuleName:  "kubernetes",
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
*/

func openshiftUpdate() error {
	modVul := common.AppModuleVul{
		VulName:     "CVE-2018-1002105",
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
