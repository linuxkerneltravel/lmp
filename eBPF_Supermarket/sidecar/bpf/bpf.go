package bpf

import (
	"os"
	"path/filepath"
)

const TraceFs = "/sys/kernel/debug/tracing"

func TracepointExists(category string, event string) bool {
	eventDir := filepath.Join(TraceFs, "events", category, event)
	fileInfo, _ := os.Stat(eventDir)
	return fileInfo.IsDir()
}
