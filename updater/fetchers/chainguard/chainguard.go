package chainguard

import (
	log "github.com/sirupsen/logrus"

	"github.com/vul-dbgen/updater"
	"github.com/vul-dbgen/updater/fetchers/chainguardv2"
)

const (
	chainguardEcosystem = "Chainguard"
	chainguardNamespace = "chainguard:rolling"
)

type ChainguardFetcher struct{}

func init() {
	updater.RegisterFetcher("chainguard", &ChainguardFetcher{})
}

func (u *ChainguardFetcher) FetchUpdate() (resp updater.FetcherResponse, err error) {
	log.WithField("package", "Chainguard").Info("Start fetching vulnerabilities")

	vulns, err := chainguardv2.FetchVulnerabilities(chainguardEcosystem, chainguardNamespace)
	if err != nil {
		return resp, err
	}
	resp.Vulnerabilities = append(resp.Vulnerabilities, vulns...)

	log.WithFields(log.Fields{"Vulnerabilities": len(resp.Vulnerabilities)}).Info("fetching chainguard done")
	return resp, nil
}

func (u *ChainguardFetcher) Clean() {
	// No cleanup needed for Chainguard fetcher
}
