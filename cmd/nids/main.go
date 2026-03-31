package main

import (
	"flag"
	"fmt"
	"log/slog"
	"nids/internal/capture"
	"nids/internal/detector"
	"nids/internal/updateips"
	"os"
)

func main() {
	updateBlacklist := flag.Bool("update-blacklist", false, "Update the IP blacklist")
	flag.Parse()

	if *updateBlacklist {
		fmt.Println("Updating blacklist...")
		err := updateips.DownloadIPs("blacklist.txt")
		if err != nil {
			fmt.Printf("Error updating blacklist: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Blacklist updated successfully.")
		return
	}

	file, err := os.OpenFile("nids.log", os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0777)
	if err != nil {
		panic(err)
	}

	defer func() {
		_ = file.Close()
	}()

	programLevel := new(slog.LevelVar) // Info by default
	programLevel.Set(slog.LevelInfo)
	handler := slog.NewJSONHandler(file, &slog.HandlerOptions{Level: programLevel})
	logger := slog.New(handler)
	slog.SetDefault(logger)

	packetCapture, err := capture.CreateOfflinePacketCapture("./data/dosattack.pcap", logger)
	// packetCapture, err := capture.CreateOfflinePacketCapture("./data/test.pcap", logger)
	// packetCapture, err := capture.CreateOnlinePacketCapture("eth0", 1600, true, logger)
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
