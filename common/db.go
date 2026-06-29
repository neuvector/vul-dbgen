package common

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"unicode"

	log "github.com/sirupsen/logrus"
)

const FirstYear = 2014

func CreateDBFile(dbFile *DBFile) error {
	log.WithFields(log.Fields{"file": dbFile.Filename}).Info("Create database file")

	header, _ := json.Marshal(dbFile.Key)

	// write to db file
	fdb, err := os.Create(dbFile.Filename)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Create db file fail")
		return err
	}
	defer fdb.Close()

	bufw := bufio.NewWriterSize(fdb, 1024*1024)

	keyLen := int32(len(header))
	if err := binary.Write(bufw, binary.BigEndian, &keyLen); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Write file header length error")
		return err
	}
	if _, err := bufw.Write(header); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Write file header error")
		return err
	}

	gzw := gzip.NewWriter(bufw)
	tw := tar.NewWriter(gzw)
	for _, file := range dbFile.Files {
		size := int64(len(file.Body))
		if file.Path != "" {
			stat, err := os.Stat(file.Path)
			if err != nil {
				log.WithFields(log.Fields{"error": err, "entry": file.Name, "path": file.Path}).Error("Stat tar source error")
				return err
			}
			size = stat.Size()
		}

		hdr := &tar.Header{
			Name:     file.Name,
			Mode:     0655,
			Typeflag: tar.TypeReg,
			Size:     size,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			log.WithFields(log.Fields{"error": err, "entry": file.Name}).Error("Write tar header error")
			return err
		}

		if file.Path != "" {
			src, err := os.Open(file.Path)
			if err != nil {
				log.WithFields(log.Fields{"error": err, "entry": file.Name, "path": file.Path}).Error("Open tar source error")
				return err
			}
			if _, err := io.Copy(tw, src); err != nil {
				_ = src.Close()
				log.WithFields(log.Fields{"error": err, "entry": file.Name, "path": file.Path}).Error("Copy tar body error")
				return err
			}
			if err := src.Close(); err != nil {
				log.WithFields(log.Fields{"error": err, "entry": file.Name, "path": file.Path}).Error("Close tar source error")
				return err
			}
			continue
		}

		if _, err := tw.Write(file.Body); err != nil {
			log.WithFields(log.Fields{"error": err, "entry": file.Name}).Error("Write tar body error")
			return err
		}
	}

	if err := tw.Close(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Close tar writer error")
		return err
	}
	if err := gzw.Close(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Close gzip writer error")
		return err
	}
	if err := bufw.Flush(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Flush file error")
		return err
	}

	stat, err := fdb.Stat()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Stat db file error")
		return err
	}

	log.WithFields(log.Fields{"file": dbFile.Filename, "size": stat.Size()}).Info("Create database done")
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
