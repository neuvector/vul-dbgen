package common

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"strconv"
	"unicode"

	log "github.com/sirupsen/logrus"

	"github.com/vul-dbgen/share"
)

const FirstYear = 2014

func CreateDBFile(dbFile *DBFile) error {
	log.WithFields(log.Fields{"file": dbFile.Filename}).Info("Create database file")

	header, _ := json.Marshal(dbFile.Key)

	buf, err := utils.MakeTar(dbFile.Files)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Make tar file error")
		return err
	}
	zb := utils.GzipBytes(buf.Bytes())

	// Use local encrypt function
	cipherData, err := encrypt(zb, getCVEDBEncryptKey())
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Encrypt tar file fail")
		return err
	}

	b0 := make([]byte, 0)
	allb := bytes.NewBuffer(b0)

	keyLen := int32(len(header))
	binary.Write(allb, binary.BigEndian, &keyLen)
	allb.Write(header)
	allb.Write(cipherData)

	// write to db file
	fdb, err := os.Create(dbFile.Filename)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Create db file fail")
		return err
	}
	defer fdb.Close()

	n, err := fdb.Write(allb.Bytes())
	if err != nil || n != allb.Len() {
		log.WithFields(log.Fields{"error": err}).Error("Write file error")
		return err
	}

	log.WithFields(log.Fields{"file": dbFile.Filename, "size": allb.Len()}).Info("Create database done")
	return nil
}

func ParseYear(name string) (int, error) {
	for i, r := range name {
		if !unicode.IsDigit(r) {
			return strconv.Atoi(name[:i])
		}
	}
	return strconv.Atoi(name)
}
