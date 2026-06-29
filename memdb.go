package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	bolt "go.etcd.io/bbolt"

	"github.com/vul-dbgen/common"
)

type memDB struct {
	keyVer      common.KeyVersion
	tbPath      string
	tmpPath     string
	storePath   string
	store       *bolt.DB
	osVulCount  int
	appVulCount int
	rawFiles    []*common.RawFile
}

func newMemDb(path string) (*memDB, error) {
	var db memDB
	db.keyVer.Keys = make(map[string]string, 0)
	db.keyVer.Shas = make(map[string]string, 0)
	return &db, nil
}

const (
	memDBStoreName    = "memdb.bolt"
	memDBOSVulBucket  = "os_vuls"
	memDBAppVulBucket = "app_vuls"
)

func (db *memDB) initStore() error {
	db.storePath = filepath.Join(db.tmpPath, memDBStoreName)

	store, err := bolt.Open(db.storePath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return err
	}

	err = store.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(memDBOSVulBucket)); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists([]byte(memDBAppVulBucket)); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		_ = store.Close()
		return err
	}

	db.store = store
	return nil
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
		Name:    fx.Feature.Name,
		Version: fx.Version.String(),
		MinVer:  fx.MinVer.String(),
	}
	return v1fx
}

func splitDb(db *memDB, dbs *dbSpace) bool {
	if db.store == nil {
		return false
	}

	err := db.store.View(func(tx *bolt.Tx) error {
		osBucket := tx.Bucket([]byte(memDBOSVulBucket))
		if osBucket == nil {
			return fmt.Errorf("missing bucket %s", memDBOSVulBucket)
		}

		if err := osBucket.ForEach(func(_, value []byte) error {
			var v common.VulFull
			if err := json.Unmarshal(value, &v); err != nil {
				return err
			}

			buf := findDBBuffer(dbs, v.Namespace)
			if buf == nil {
				return fmt.Errorf("no known namespace found: %s", v.Namespace)
			}

			vs := vulToShort(&v)
			b, err := json.Marshal(vs)
			if err == nil {
				if err := buf.indexData.WriteLine(b); err != nil {
					return err
				}
			}

			b, err = json.Marshal(&v)
			if err == nil {
				if err := buf.fullData.WriteLine(b); err != nil {
					return err
				}
			}

			return nil
		}); err != nil {
			return err
		}

		appBucket := tx.Bucket([]byte(memDBAppVulBucket))
		if appBucket == nil {
			return fmt.Errorf("missing bucket %s", memDBAppVulBucket)
		}

		return appBucket.ForEach(func(_, value []byte) error {
			return dbs.appData.WriteLine(value)
		})
	})
	if err != nil {
		log.WithError(err).Error("Split database error")
		return false
	}

	for i := 0; i < dbMax; i++ {
		buf := &dbs.buffers[i]
		sum, err := buf.indexData.Close()
		if err != nil {
			log.WithFields(log.Fields{"error": err, "file": buf.indexData.path}).Error("Close staged index file error")
			return false
		}
		buf.indexSHA = sum

		sum, err = buf.fullData.Close()
		if err != nil {
			log.WithFields(log.Fields{"error": err, "file": buf.fullData.path}).Error("Close staged full file error")
			return false
		}
		buf.fullSHA = sum
	}

	sum, err := dbs.appData.Close()
	if err != nil {
		log.WithFields(log.Fields{"error": err, "file": dbs.appData.path}).Error("Close staged app file error")
		return false
	}
	dbs.appSHA = sum

	for i, v := range db.rawFiles {
		dbs.rawSHA[i] = sha256.Sum256(v.Raw)
	}

	return true
}

func findDBBuffer(dbs *dbSpace, namespace string) *dbBuffer {
	for i := 0; i < dbMax; i++ {
		if strings.Contains(namespace, dbs.buffers[i].namespace) {
			return &dbs.buffers[i]
		}
	}
	return nil
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
	dbPhoton
	dbRocky
	dbWolfi
	dbChainguard
	dbMax
)

type dbBuffer struct {
	namespace string
	indexFile string
	fullFile  string
	indexData stagedFile
	fullData  stagedFile
	indexSHA  [sha256.Size]byte
	fullSHA   [sha256.Size]byte
}

type dbSpace struct {
	buffers [dbMax]dbBuffer
	appData stagedFile
	appSHA  [sha256.Size]byte
	rawSHA  [][sha256.Size]byte
}

type stagedFile struct {
	path   string
	file   *os.File
	writer *bufio.Writer
	hasher hash.Hash
	size   int64
}

func newStagedFile(dir, name string) (stagedFile, error) {
	path := filepath.Join(dir, name)
	file, err := os.Create(path)
	if err != nil {
		return stagedFile{}, err
	}

	return stagedFile{
		path:   path,
		file:   file,
		writer: bufio.NewWriterSize(file, 1024*1024),
		hasher: sha256.New(),
	}, nil
}

func (sf *stagedFile) WriteLine(body []byte) error {
	n, err := sf.writer.Write(body)
	if err != nil {
		return err
	}
	if _, err := sf.hasher.Write(body[:n]); err != nil {
		return err
	}
	sf.size += int64(n)

	if err := sf.writer.WriteByte('\n'); err != nil {
		return err
	}
	if _, err := sf.hasher.Write([]byte{'\n'}); err != nil {
		return err
	}
	sf.size++
	return nil
}

func (sf *stagedFile) Close() ([sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	if sf.writer != nil {
		if err := sf.writer.Flush(); err != nil {
			return sum, err
		}
	}
	if sf.file != nil {
		if err := sf.file.Close(); err != nil {
			return sum, err
		}
		sf.file = nil
	}
	copy(sum[:], sf.hasher.Sum(nil))
	return sum, nil
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
	dbs.buffers[dbPhoton] = dbBuffer{namespace: "photon", indexFile: "photon_index.tb", fullFile: "photon_full.tb"}
	dbs.buffers[dbRocky] = dbBuffer{namespace: "rocky", indexFile: "rocky_index.tb", fullFile: "rocky_full.tb"}
	dbs.buffers[dbWolfi] = dbBuffer{namespace: "wolfi", indexFile: "wolfi_index.tb", fullFile: "wolfi_full.tb"}
	dbs.buffers[dbChainguard] = dbBuffer{namespace: "chainguard", indexFile: "chainguard_index.tb", fullFile: "chainguard_full.tb"}

	for i := 0; i < dbMax; i++ {
		indexData, err := newStagedFile(db.tmpPath, dbs.buffers[i].indexFile)
		if err != nil {
			log.WithFields(log.Fields{"error": err, "file": dbs.buffers[i].indexFile}).Error("Create staged index file error")
			return false
		}
		fullData, err := newStagedFile(db.tmpPath, dbs.buffers[i].fullFile)
		if err != nil {
			log.WithFields(log.Fields{"error": err, "file": dbs.buffers[i].fullFile}).Error("Create staged full file error")
			return false
		}
		dbs.buffers[i].indexData = indexData
		dbs.buffers[i].fullData = fullData
	}

	appData, err := newStagedFile(db.tmpPath, "apps.tb")
	if err != nil {
		log.WithFields(log.Fields{"error": err, "file": "apps.tb"}).Error("Create staged app file error")
		return false
	}
	dbs.appData = appData

	dbs.rawSHA = make([][sha256.Size]byte, len(db.rawFiles))

	ok := splitDb(db, &dbs)
	if !ok {
		log.Error("Split database error")
		return false
	}
	common.LogMemStats("after-split-db")

	log.WithFields(log.Fields{"vuls": db.osVulCount, "appVuls": db.appVulCount}).Info()

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

		var files []common.DBFileEntry
		for _, i := range []int{dbUbuntu, dbDebian, dbCentos, dbAlpine} {
			buf := &dbs.buffers[i]
			files = append(files, common.DBFileEntry{Name: buf.indexFile, Path: buf.indexData.path})
			files = append(files, common.DBFileEntry{Name: buf.fullFile, Path: buf.fullData.path})
		}
		files = append(files, common.DBFileEntry{Name: "apps.tb", Path: dbs.appData.path})

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

		var files []common.DBFileEntry
		for i := 0; i < dbMax; i++ {
			buf := &dbs.buffers[i]
			files = append(files, common.DBFileEntry{Name: buf.indexFile, Path: buf.indexData.path})
			files = append(files, common.DBFileEntry{Name: buf.fullFile, Path: buf.fullData.path})
			log.WithFields(log.Fields{"database": buf.namespace, "size": buf.fullData.size}).Info()
		}
		files = append(files, common.DBFileEntry{Name: "apps.tb", Path: dbs.appData.path})
		log.WithFields(log.Fields{"database": "apps", "size": dbs.appData.size}).Info()
		for i, v := range db.rawFiles {
			files = append(files, common.DBFileEntry{Name: v.Name, Body: v.Raw})
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
	common.LogMemStats("after-write-db")

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
	if dbErr == nil {
		dbErr = db.initStore()
	}
	return db, dbErr
}

func (db *memDB) InsertVulnerabilities(osVuls []*common.Vulnerability, appVuls []*common.AppModuleVul, rawFiles []*common.RawFile) error {
	if db.store == nil {
		return fmt.Errorf("memdb store is not initialized")
	}

	err := db.store.Update(func(tx *bolt.Tx) error {
		osBucket := tx.Bucket([]byte(memDBOSVulBucket))
		appBucket := tx.Bucket([]byte(memDBAppVulBucket))
		if osBucket == nil || appBucket == nil {
			return fmt.Errorf("memdb buckets not initialized")
		}

		for _, v := range osVuls {
			vv1 := modVulToVulFull(v)
			for _, fx := range v.FixedIn {
				v1fx := modFeaToFeaFull(fx)
				vv1.FixedIn = append(vv1.FixedIn, v1fx)
			}
			cveName := fmt.Sprintf("%s:%s", vv1.Namespace, vv1.Name)

			payload, err := json.Marshal(vv1)
			if err != nil {
				return err
			}
			if err := osBucket.Put([]byte(cveName), payload); err != nil {
				return err
			}
		}

		for i, appVul := range appVuls {
			payload, err := json.Marshal(appVul)
			if err != nil {
				return err
			}

			key := make([]byte, 8)
			binary.BigEndian.PutUint64(key, uint64(i))
			if err := appBucket.Put(key, payload); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	db.osVulCount = len(osVuls)
	db.appVulCount = len(appVuls)

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
	if db.store != nil {
		_ = db.store.Close()
	}
	os.RemoveAll(db.tmpPath)
}
