package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/vul-dbgen/common"
	utils "github.com/vul-dbgen/share"
)

type memDB struct {
	keyVer   common.KeyVersion
	tbPath   string
	tmpPath  string
	osVuls   map[string]*common.VulFull
	appVuls  []*common.AppModuleVul
	rawFiles []*common.RawFile
}

func newMemDb(path string) (*memDB, error) {
	var db memDB
	db.osVuls = make(map[string]*common.VulFull, 0)
	db.keyVer.Keys = make(map[string]string, 0)
	db.keyVer.Shas = make(map[string]string, 0)
	return &db, nil
}

func vulToShort(v *common.VulFull) *common.VulShort {
	var vs = common.VulShort{
		Name:      v.Name,
		Namespace: v.Namespace,
		CPEs:      v.CPEs,
	}
	for _, ft := range v.FixedIn {
		var f common.FeaShort
		f.Name = ft.Name
		f.Version = ft.Version
		f.MinVer = ft.MinVer
		vs.Fixin = append(vs.Fixin, f)
	}
	return &vs
}

func modVulToVulFull(v *common.Vulnerability) *common.VulFull {
	var vv1 common.VulFull
	vv1.Name = v.Name
	vv1.Namespace = v.Namespace
	vv1.Description = v.Description
	vv1.Link = v.Link
	vv1.Severity = v.Severity
	vv1.FeedRating = v.FeedRating
	vv1.CPEs = v.CPEs
	vv1.CVEs = make([]string, len(v.CVEs))
	for i, cve := range v.CVEs {
		vv1.CVEs[i] = cve.Name
	}
	vv1.CVSSv2 = v.CVSSv2
	vv1.CVSSv3 = v.CVSSv3
	vv1.IssuedDate = v.IssuedDate
	vv1.LastModDate = v.LastModDate

	return &vv1
}

func modFeaToFeaFull(fx common.FeatureVersion) common.FeaFull {
	var v1fx = common.FeaFull{
		Name:      fx.Feature.Name,
		Namespace: fx.Feature.Namespace,
		Version:   fx.Version.String(),
		MinVer:    fx.MinVer.String(),
	}
	return v1fx
}

func splitDb(db *memDB, dbs *dbSpace) bool {
	if db.osVuls == nil {
		return false
	}

	for _, v := range db.osVuls {
		var buf *dbBuffer
		for i := 0; i < dbMax; i++ {
			if strings.Contains(v.Namespace, dbs.buffers[i].namespace) {
				buf = &dbs.buffers[i]
				break
			}
		}

		if buf == nil {
			log.Error("No known namespace found:", v.Namespace)
			return false
		}

		vs := vulToShort(v)
		b, err := json.Marshal(vs)
		if err == nil {
			buf.indexBuf.WriteString(fmt.Sprintf("%s\n", b))
		}
		b, err = json.Marshal(v)
		if err == nil {
			buf.fullBuf.WriteString(fmt.Sprintf("%s\n", b))
		}
	}

	for i := 0; i < dbMax; i++ {
		buf := &dbs.buffers[i]
		buf.indexSHA = sha256.Sum256(buf.indexBuf.Bytes())
		buf.fullSHA = sha256.Sum256(buf.fullBuf.Bytes())
	}

	for _, v := range db.appVuls {
		if b, err := json.Marshal(&v); err == nil {
			dbs.appBuf.WriteString(fmt.Sprintf("%s\n", b))
		}
	}
	dbs.appSHA = sha256.Sum256(dbs.appBuf.Bytes())

	for i, v := range db.rawFiles {
		dbs.rawSHA[i] = sha256.Sum256(v.Raw)
	}

	return true
}

var rawFilenames []string = []string{
	common.RHELCpeMapFile,
}

const (
	dbUbuntu = iota
	dbDebian
	dbCentos
	dbAlpine
	dbAmazon
	dbOracle
	dbMariner
	dbSuse
	dbMax
)

type dbBuffer struct {
	namespace string
	indexFile string
	fullFile  string
	indexBuf  bytes.Buffer
	fullBuf   bytes.Buffer
	indexSHA  [sha256.Size]byte
	fullSHA   [sha256.Size]byte
}

type dbSpace struct {
	buffers [dbMax]dbBuffer
	appBuf  bytes.Buffer
	appSHA  [sha256.Size]byte
	rawSHA  [][sha256.Size]byte
}

func (db *memDB) UpdateDb(version string) bool {
	// if len(db.vuls) == 0 {
	// 		log.Errorf("CVE update FAIL")
	// 		return false
	// 	}

	var dbs dbSpace
	dbs.buffers[dbUbuntu] = dbBuffer{namespace: "ubuntu", indexFile: "ubuntu_index.tb", fullFile: "ubuntu_full.tb"}
	dbs.buffers[dbDebian] = dbBuffer{namespace: "debian", indexFile: "debian_index.tb", fullFile: "debian_full.tb"}
	dbs.buffers[dbCentos] = dbBuffer{namespace: "centos", indexFile: "centos_index.tb", fullFile: "centos_full.tb"}
	dbs.buffers[dbAlpine] = dbBuffer{namespace: "alpine", indexFile: "alpine_index.tb", fullFile: "alpine_full.tb"}
	dbs.buffers[dbAmazon] = dbBuffer{namespace: "amzn", indexFile: "amazon_index.tb", fullFile: "amazon_full.tb"}
	dbs.buffers[dbOracle] = dbBuffer{namespace: "oracle", indexFile: "oracle_index.tb", fullFile: "oracle_full.tb"}
	dbs.buffers[dbMariner] = dbBuffer{namespace: "mariner", indexFile: "mariner_index.tb", fullFile: "mariner_full.tb"}
	dbs.buffers[dbSuse] = dbBuffer{namespace: "sles", indexFile: "suse_index.tb", fullFile: "suse_full.tb"}

	dbs.rawSHA = make([][sha256.Size]byte, len(db.rawFiles))

	ok := splitDb(db, &dbs)
	if !ok {
		log.Error("Split database error")
		return false
	}

	log.WithFields(log.Fields{"vuls": len(db.osVuls), "appVuls": len(db.appVuls)}).Info()

	var compactDB common.DBFile
	var regularDB common.DBFile

	// Compact database is consumed by scanners running inside controller. This scanner
	// in old versions cannot parse the regular db because of the header size limit
	// No new entries should be added !!!
	{
		keyVer := common.KeyVersion{
			Version:    version,
			UpdateTime: time.Now().Format(time.RFC3339),
			Keys:       db.keyVer.Keys,
			Shas:       make(map[string]string, 0),
		}

		for _, i := range []int{dbUbuntu, dbDebian, dbCentos, dbAlpine} {
			buf := &dbs.buffers[i]
			keyVer.Shas[buf.indexFile] = fmt.Sprintf("%x", buf.indexSHA)
			keyVer.Shas[buf.fullFile] = fmt.Sprintf("%x", buf.fullSHA)
		}
		keyVer.Shas["apps.tb"] = fmt.Sprintf("%x", dbs.appSHA)

		var files []utils.TarFileInfo
		for _, i := range []int{dbUbuntu, dbDebian, dbCentos, dbAlpine} {
			buf := &dbs.buffers[i]
			files = append(files, utils.TarFileInfo{buf.indexFile, buf.indexBuf.Bytes()})
			files = append(files, utils.TarFileInfo{buf.fullFile, buf.fullBuf.Bytes()})
		}
		files = append(files, utils.TarFileInfo{"apps.tb", dbs.appBuf.Bytes()})

		compactDB.Filename = db.tbPath + common.CompactCVEDBName
		compactDB.Key = keyVer
		compactDB.Files = files
	}

	// regular files
	{
		keyVer := common.KeyVersion{
			Version:    version,
			UpdateTime: time.Now().Format(time.RFC3339),
			Keys:       db.keyVer.Keys,
			Shas:       make(map[string]string, 0),
		}

		for i := 0; i < dbMax; i++ {
			buf := &dbs.buffers[i]
			keyVer.Shas[buf.indexFile] = fmt.Sprintf("%x", buf.indexSHA)
			keyVer.Shas[buf.fullFile] = fmt.Sprintf("%x", buf.fullSHA)
		}
		keyVer.Shas["apps.tb"] = fmt.Sprintf("%x", dbs.appSHA)

		var files []utils.TarFileInfo
		for i := 0; i < dbMax; i++ {
			buf := &dbs.buffers[i]
			files = append(files, utils.TarFileInfo{buf.indexFile, buf.indexBuf.Bytes()})
			files = append(files, utils.TarFileInfo{buf.fullFile, buf.fullBuf.Bytes()})
			log.WithFields(log.Fields{"database": buf.namespace, "size": buf.fullBuf.Len()}).Info()
		}
		files = append(files, utils.TarFileInfo{"apps.tb", dbs.appBuf.Bytes()})
		log.WithFields(log.Fields{"database": "apps", "size": dbs.appBuf.Len()}).Info()
		for i, v := range db.rawFiles {
			files = append(files, utils.TarFileInfo{v.Name, v.Raw})
			keyVer.Shas[v.Name] = fmt.Sprintf("%x", dbs.rawSHA[i])
			log.WithFields(log.Fields{"database": v.Name, "size": len(v.Raw)}).Info()
		}

		regularDB.Filename = db.tbPath + common.RegularCVEDBName
		regularDB.Key = keyVer
		regularDB.Files = files
	}

	for _, dbf := range []*common.DBFile{&compactDB, &regularDB} {
		common.CreateDBFile(dbf)
	}

	return true
}

func memdbOpen(path string) (*memDB, error) {
	dir, err := ioutil.TempDir("", "cve")
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to create tmp cve directory")
		return nil, err
	}
	db, dbErr := newMemDb(path)
	db.tbPath = path
	db.tmpPath = dir
	return db, dbErr
}

func (db *memDB) InsertVulnerabilities(osVuls []*common.Vulnerability, appVuls []*common.AppModuleVul, rawFiles []*common.RawFile) error {
	for _, v := range osVuls {
		vv1 := modVulToVulFull(v)
		for _, fx := range v.FixedIn {
			v1fx := modFeaToFeaFull(fx)
			vv1.FixedIn = append(vv1.FixedIn, v1fx)
		}
		cveName := fmt.Sprintf("%s:%s", vv1.Namespace, vv1.Name)
		db.osVuls[cveName] = vv1
	}
	db.appVuls = appVuls

	db.rawFiles = rawFiles
	// If a raw file is missing, add an empty file
	for _, name := range rawFilenames {
		found := false
		for i, _ := range db.rawFiles {
			if db.rawFiles[i].Name == name {
				found = true
				break
			}
		}
		if !found {
			db.rawFiles = append(db.rawFiles, &common.RawFile{Name: name, Raw: make([]byte, 0)})
		}
	}

	return nil
}

func (db *memDB) Close() {
	os.RemoveAll(db.tmpPath)
}
