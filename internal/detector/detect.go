/*
This module deals with detection of malicious packets coming from capture module
*/
package detector

import (
	"bufio"
	"io"
	"log/slog"

	"nids/internal/trie"
	"nids/internal/updateips"
	"nids/internal/utils"

	"github.com/google/gopacket"
)

/*
# Engine - Finds malicious ips and patterns
  - AlertCount - Counts the total number of alerts detected till now
  - Trie - Data structure stores
  - Logger - Logs errors
*/
type Engine struct {
	AlertCount int
	Logger     *slog.Logger
	Trie       *trie.Trie
}

/*
Creates a new engine for malicious IP Detection
*/
func NewEngine(Logger *slog.Logger) (*Engine, error) {
	// ! WARNING: CONFIG
	ipTrie, err := updateips.GetIPTrie("blacklist.txt")

	if err != nil {
		return nil, err
	}

	engine := &Engine{
		AlertCount: 0,
		Logger:     Logger,
		Trie:       ipTrie,
	}

	return engine, nil
}

/*
Detects is there are any malicious ips involved in communication
*/
func (e *Engine) Detect(netFlow, tcpFlow gopacket.Flow, streamLogger *slog.Logger) {
	streamLogger.Info("Stream analysis started")
	src := netFlow.Src().String()
	dst := netFlow.Dst().String()

	if isPresent, err := e.Trie.IsIPBlockPresent(src); err == nil && isPresent {
		if isTrusted, err := utils.IsIPTrusted(src); err == nil && !isTrusted {
			streamLogger.Warn("Source IP Malicious")
			e.AlertCount += 1
		}
	}
	if isPresent, err := e.Trie.IsIPBlockPresent(dst); err == nil && isPresent {
		if isTrusted, err := utils.IsIPTrusted(dst); err == nil && !isTrusted {
			streamLogger.Warn("Destination IP Malicious")
			e.AlertCount += 1
		}
	}
}

/*
Reads all the bytes of the stream
*/
func (e *Engine) ReadBytes(r *bufio.Reader, streamLogger *slog.Logger) {
	streamLogger.Info(
		"Starting capturing data",
	)

	data, err := io.ReadAll(r)
	if err != nil && err != io.EOF {
		e.Logger.Error("Read error", "err", err)
	}

	streamLogger.Info(
		"Captured all data",
		"len", len(data),
	)
}
