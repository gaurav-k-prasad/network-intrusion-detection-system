package main

import (
	"log/slog"
	"nids/internal/capture"
	"nids/internal/detector"
	"os"
)

func main() {
	file, err := os.OpenFile("nids.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}

	defer file.Close()

	handler := slog.NewJSONHandler(file, nil)
	// handler := slog.NewTextHandler(os.Stdout, nil)
	logger := slog.New(handler)
	slog.SetDefault(logger)

	// packetCapture, err := capture.CreateOfflinePacketCapture("./data/test.pcap", logger)
	packetCapture, err := capture.CreateOnlinePacketCapture("eth0", 1600, true, logger)
	if err != nil {
		slog.Error("Error creating capture", "error", err)
		os.Exit(1)
	}

	defer packetCapture.Close()

	engine := detector.NewEngine([]string{"malware", "attack", "exploit"}, logger.With("module", "engine"))

	packetCapture.StartProcessing(engine)
}
