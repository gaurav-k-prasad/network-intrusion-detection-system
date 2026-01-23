package detector

import (
	"bufio"
	"io"
	"log/slog"

	"github.com/google/gopacket"
)

type Engine struct {
	Signatures []string
	AlertCount int
	Logger     *slog.Logger
}

func NewEngine(sigs []string, Logger *slog.Logger) *Engine {
	return &Engine{Signatures: sigs, AlertCount: 0, Logger: Logger}
}

func (e *Engine) Detect(netFlow, tcpFlow gopacket.Flow, r *bufio.Reader, streamLogger *slog.Logger) {
	data, err := io.ReadAll(r)
	if err != nil && err != io.EOF {
		e.Logger.Error("Read error", "err", err)
	}
	streamLogger.Info("Captured all data", "len", len(data), "data", string(data))
	streamLogger.Info("Stream analysis started")
}
