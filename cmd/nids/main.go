package main

import (
	"log/slog"
	"nids/internal/capture"
	"nids/internal/detector"
	"os"
)

func main() {
	file, err := os.OpenFile("nids.log", os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0777)
	if err != nil {
		panic(err)
	}

	defer func() {
		_ = file.Close()
	}()

	programLevel := new(slog.LevelVar) // Info by default
	programLevel.Set(slog.LevelWarn)
	handler := slog.NewJSONHandler(file, &slog.HandlerOptions{Level: programLevel})
	// handler := slog.NewJSONHandler(file, nil)
	// handler := slog.NewTextHandler(os.Stdout, nil)
	logger := slog.New(handler)
	slog.SetDefault(logger)

	// packetCapture, err := capture.CreateOfflinePacketCapture("./data/test.pcap", logger)
	packetCapture, err := capture.CreateOnlinePacketCapture("eth0", 1600, true, logger)
	if err != nil {
		slog.Error("Error creating capture", "error", err)
		panic(err)
	}

	defer packetCapture.Close()

	engine, err := detector.NewEngine(logger.With("module", "engine"))
	if err != nil {
		panic(err)
	}

	packetCapture.StartProcessing(engine)
}
