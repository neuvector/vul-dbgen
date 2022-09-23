package apps

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/vul-dbgen/common"
	"github.com/vul-dbgen/updater"
)

const (
	k8sDataFile = "apps/k8s.json.gz"
)

type k8sItem struct {
	ID      string `json:"id"`
	URL     string `json:"url"`
	Summary string `json:"summary"`
}

type k8sData struct {
	Version     string    `json:"version"`
	FeedURL     string    `json:"feed_url"`
	Description string    `json:"description"`
	Items       []k8sItem `json:"items"`
}

func k8sUpdate() error {
	log.Info("fetching kubernetes vulnerabilities")

	dataFile := fmt.Sprintf("%s%s", updater.CVESourceRoot, k8sDataFile)
	f, err := os.Open(dataFile)
	if err != nil {
		log.WithFields(log.Fields{"file": dataFile}).Error("Cannot find local database")
		return fmt.Errorf("Unabled to fetch any vulernabilities")
	}

	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		log.WithFields(log.Fields{"file": dataFile}).Error("Failed to create feed reader")
		return fmt.Errorf("Unabled to fetch any vulernabilities")
	}
	defer gzr.Close()

	byteValue, _ := ioutil.ReadAll(gzr)

	var data k8sData
	if err = json.Unmarshal(byteValue, &data); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to unmarshal the feed")
		return fmt.Errorf("Unabled to fetch any vulernabilities")
	}

	var count int
	for _, v := range data.Items {
		// We pretty much can only use the CVE ID and have to query NVD for everything else.
		modVul := common.AppModuleVul{
			VulName:     v.ID,
			Description: v.Summary,
			ModuleName:  "kubernetes",
			Link:        v.URL,
			CVEs:        []string{v.ID},
		}

		addAppVulMap(&modVul)
		count++
	}

	if count == 0 {
		log.WithFields(log.Fields{"cve": count}).Error()
		return fmt.Errorf("Unabled to fetch any vulernabilities")
	}

	log.WithFields(log.Fields{"cve": count}).Info()
	return nil
}
