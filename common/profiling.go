package common

import (
	"os"
	"runtime"
	runtimepprof "runtime/pprof"

	log "github.com/sirupsen/logrus"
)

var memStatsEnabled bool

func SetMemStatsEnabled(enabled bool) {
	memStatsEnabled = enabled
}

func LogMemStats(stage string) {
	if !memStatsEnabled {
		return
	}

	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	log.WithFields(log.Fields{
		"stage":          stage,
		"alloc_mb":       bToMB(stats.Alloc),
		"heap_alloc_mb":  bToMB(stats.HeapAlloc),
		"heap_sys_mb":    bToMB(stats.HeapSys),
		"heap_idle_mb":   bToMB(stats.HeapIdle),
		"heap_inuse_mb":  bToMB(stats.HeapInuse),
		"stack_inuse_mb": bToMB(stats.StackInuse),
		"sys_mb":         bToMB(stats.Sys),
		"num_gc":         stats.NumGC,
	}).Info("MemStats")
}

func WriteHeapProfile(path string) error {
	runtime.GC()

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return runtimepprof.WriteHeapProfile(file)
}

func bToMB(v uint64) uint64 {
	return v / 1024 / 1024
}
