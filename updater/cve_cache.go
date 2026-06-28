package updater

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	bolt "go.etcd.io/bbolt"

	"github.com/vul-dbgen/common"
)

const (
	cveCacheBucket = "cveMap"
	cveCacheDBPath = "/tmp/cve_cache.db"
)

var cveCache *bolt.DB

// initCveCache initializes the bbolt database for cveMap
func initCveCache() error {
	dbPath := os.Getenv("CVE_CACHE_PATH")
	if dbPath == "" {
		dbPath = cveCacheDBPath
	}

	// Remove stale database
	os.Remove(dbPath)

	// Open bbolt database
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return fmt.Errorf("failed to open cve cache: %w", err)
	}

	cveCache = db

	// Create bucket
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(cveCacheBucket))
		return err
	})

	if err != nil {
		db.Close()
		return fmt.Errorf("failed to create cve cache bucket: %w", err)
	}

	log.WithField("path", dbPath).Info("Initialized CVE cache database")
	return nil
}

// putCveMetadata stores enriched CVE metadata in cache
func putCveMetadata(key string, meta *common.NVDMetadata) error {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(meta); err != nil {
		return err
	}

	return cveCache.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(cveCacheBucket))
		return b.Put([]byte(key), buf.Bytes())
	})
}

// getCveMetadata retrieves enriched CVE metadata from cache
func getCveMetadata(key string) (*common.NVDMetadata, bool) {
	var meta common.NVDMetadata

	err := cveCache.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(cveCacheBucket))
		data := b.Get([]byte(key))
		if data == nil {
			return fmt.Errorf("not found")
		}

		dec := gob.NewDecoder(bytes.NewReader(data))
		return dec.Decode(&meta)
	})

	if err != nil {
		return nil, false
	}

	return &meta, true
}

// closeCveCache closes the cache database and removes temp files
func closeCveCache() {
	if cveCache != nil {
		dbPath := cveCacheDBPath
		if p := os.Getenv("CVE_CACHE_PATH"); p != "" {
			dbPath = p
		}

		cveCache.Close()
		os.Remove(dbPath)

		log.WithField("path", dbPath).Info("Cleaned up CVE cache database")
	}
}
