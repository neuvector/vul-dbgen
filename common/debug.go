package common

import (
	"strings"

	log "github.com/sirupsen/logrus"
	utils "github.com/vul-dbgen/share"
)

type DebugFilter struct {
	Enabled bool
	CVEs    utils.Set
}

var Debugs DebugFilter

func ParseDebugFilters(s string) {
	Debugs.Enabled = true
	Debugs.CVEs = utils.NewSet()

	tokens := strings.Split(s, ",")
	for _, token := range tokens {
		kvs := strings.Split(token, "=")
		if len(kvs) >= 2 {
			switch kvs[0] {
			case "v":
				vuls := strings.Split(kvs[1], ",")
				for _, v := range vuls {
					Debugs.CVEs.Add(v)
				}
				log.WithFields(log.Fields{"vuls": Debugs.CVEs}).Debug("vulnerability filter")
			}
		}
	}
}

func DEBUG_SEVERITY(x interface{}, msg string) {
	if v, ok := x.(*Vulnerability); ok {
		if Debugs.Enabled {
			if Debugs.CVEs.Contains(v.Name) {
				log.WithFields(log.Fields{
					"name": v.Name, "distro": v.Namespace, "severity": v.Severity, "v2": v.CVSSv2, "v3": v.CVSSv3, "rate": v.FeedRating,
				}).Debug(msg)
			}
		}
	} else if app, ok := x.(*AppModuleVul); ok {
		if Debugs.Enabled {
			if Debugs.CVEs.Contains(app.VulName) {
				log.WithFields(log.Fields{
					"name": app.VulName, "module": app.ModuleName, "severity": app.Severity, "v2": app.Score, "v3": app.ScoreV3,
				}).Debug(msg)
			}
		}
	}
}
