package wolfi

import (
	log "github.com/sirupsen/logrus"

	"github.com/vul-dbgen/updater"
	"github.com/vul-dbgen/updater/fetchers/chainguardv2"
)

const (
	wolfiEcosystem = "Wolfi"
	wolfiNamespace = "wolfi:rolling"
)

type WolfiFetcher struct{}

func init() {
	updater.RegisterFetcher("wolfi", &WolfiFetcher{})
}

func (u *WolfiFetcher) FetchUpdate() (resp updater.FetcherResponse, err error) {
	log.WithField("package", "Wolfi").Info("Start fetching vulnerabilities")

	vulns, err := chainguardv2.FetchVulnerabilities(wolfiEcosystem, wolfiNamespace)
	if err != nil {
		return resp, err
	}
	resp.Vulnerabilities = append(resp.Vulnerabilities, vulns...)

	log.WithFields(log.Fields{"Vulnerabilities": len(resp.Vulnerabilities)}).Info("fetching wolfi done")
	return resp, nil
}

func (u *WolfiFetcher) Clean() {
	// No cleanup needed for Wolfi fetcher
}
