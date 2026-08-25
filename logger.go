package main

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

type logEntry struct {
	Timestamp string `json:"timestamp"`
	Event     string `json:"event"`
	Hostname  string `json:"hostname,omitempty"`
	Domain    string `json:"domain,omitempty"` // the blocklist entry that matched
	SrcIP     string `json:"srcIp,omitempty"`
	SrcPort   uint16 `json:"srcPort,omitempty"`
	DstIP     string `json:"dstIp,omitempty"`
	DstPort   uint16 `json:"dstPort,omitempty"`
	Path      string `json:"path,omitempty"`
	Process   string `json:"process,omitempty"`
	PID       uint32 `json:"pid,omitempty"`
}

// logger appends one JSON line per event, flushing immediately — event
// volume here is low (only inspected/blocked flows get logged, not every
// packet), so unlike gil-sec's buffered Node logger there's no need to batch.
type logger struct {
	mu   sync.Mutex
	file *os.File
}

func newLogger(path string) (*logger, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &logger{file: f}, nil
}

func (l *logger) log(e logEntry) {
	e.Timestamp = time.Now().UTC().Format(time.RFC3339)

	l.mu.Lock()
	defer l.mu.Unlock()

	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	l.file.Write(append(data, '\n'))
}

func (l *logger) close() {
	l.file.Close()
}
