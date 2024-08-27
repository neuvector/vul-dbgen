package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/vul-dbgen/common"
	utils "github.com/vul-dbgen/share"
	"github.com/vul-dbgen/updater"

	_ "github.com/vul-dbgen/updater/fetchers/alpine"
	_ "github.com/vul-dbgen/updater/fetchers/amazon"
	_ "github.com/vul-dbgen/updater/fetchers/apps"
	_ "github.com/vul-dbgen/updater/fetchers/debian"
	_ "github.com/vul-dbgen/updater/fetchers/mariner"
	_ "github.com/vul-dbgen/updater/fetchers/oracle"
	_ "github.com/vul-dbgen/updater/fetchers/photon"
	_ "github.com/vul-dbgen/updater/fetchers/rhel2"
	_ "github.com/vul-dbgen/updater/fetchers/rocky"
	_ "github.com/vul-dbgen/updater/fetchers/suse"
	_ "github.com/vul-dbgen/updater/fetchers/ubuntu"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: dbgen [OPTIONS]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&utils.LogFormatter{Module: "DBG"})

	version := flag.String("v", "0.90", "cve database version")
	dbPath := flag.String("d", "", "cve database path")
	debug := flag.String("debug", "", "debug filters. -debug v=CVE-2023-1000")
	flag.Usage = usage
	flag.Parse()

	_, err := strconv.ParseFloat(*version, 64)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Parse version fail")
		os.Exit(2)
	}

	if *debug != "" {
		common.ParseDebugFilters(*debug)
	}

	done := make(chan bool, 1)
	c_sig := make(chan os.Signal, 1)
	signal.Notify(c_sig, os.Interrupt, syscall.SIGTERM)

	db, err := memdbOpen(*dbPath)
	if err != nil {
		os.Exit(2)
	}
	go func() {
		if updater.Update(db) == false {
			os.Exit(2)
		}
		if db.UpdateDb(*version) == false {
			os.Exit(2)
		}
		db.Close()
		done <- true
	}()

	go func() {
		<-c_sig
		done <- true
	}()

	<-done

	log.Info("Update CVE database successfully")
}
