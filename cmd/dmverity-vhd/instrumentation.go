package main

import (
	"os"
	"runtime"
	"runtime/pprof"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func setLoggingLevel(ctx *cli.Context) {
	verbose := ctx.GlobalBool(verboseFlag)
	if verbose {
		log.SetLevel(log.DebugLevel)
	}
	trace := ctx.GlobalBool(traceFlag)
	if trace {
		log.SetLevel(log.TraceLevel)
	}
}

var profilerEnabled bool = false

func setupProfiler(ctx *cli.Context) {
	profilerPath := ctx.GlobalString(profilerFlag)

	if len(profilerPath) > 0 {
		f, err := os.Create(profilerPath)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		profilerEnabled = true
	}
}

func stopProfiler(ctx *cli.Context) {
	if profilerEnabled {
		pprof.StopCPUProfile()
	}
}

func TraceMemUsage() {
	if log.IsLevelEnabled(log.TraceLevel) {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		log.Tracef("Alloc = %v TotalAlloc = %v Sys = %v NumGC = %v", m.Alloc/1024/1024, m.TotalAlloc/1024/1024, m.Sys/1024/1024, m.NumGC)
	}
}

func TraceMemUsageDesc(desc string) {
	if log.IsLevelEnabled(log.TraceLevel) {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		log.Tracef("%s: Alloc = %v TotalAlloc = %v Sys = %v NumGC = %v", desc, m.Alloc/1024/1024, m.TotalAlloc/1024/1024, m.Sys/1024/1024, m.NumGC)
	}
}
