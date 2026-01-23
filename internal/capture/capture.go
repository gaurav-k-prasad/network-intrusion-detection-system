/*
This module deals with capturing the packet on basis of how it's called (online packet capture / offline packet capture)
*/

package capture

import (
	"bufio"
	"fmt"
	"log/slog"
	"nids/internal/detector"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

/*
# Configuration for Online packet capture
  - Device - Network device
  - Snapshot length - Length of snapshot(usually >1500)
  - Promiscuous - Allows to inspect all packets no matter destination
*/
type OnlineConfig struct {
	Device         string
	SnapshotLength int32
	Promiscuous    bool
}

/*
# Configuration for offline packet capture
  - FilePath - Valid path for the .pcap file
*/
type OfflineConfig struct {
	FilePath string
}

/*
# Consists of all required data about pacture capture module
  - IsOnline - If the capture module is running on online/offline mode
  - Online/Offline - Required configs
  - PacketSource - Packet source for capturing
  - Logger - Required logger to log outputs
*/
type PacketCapture struct {
	IsOnline     bool
	Online       OnlineConfig
	Offline      OfflineConfig
	PacketSource *gopacket.PacketSource
	handle       *pcap.Handle
	Logger       *slog.Logger
}

/*
Creates online pacet capture using given parameters
*/
func CreateOnlinePacketCapture(device string, snapshotLength int32, promiscuous bool, logger *slog.Logger) (*PacketCapture, error) {
	if device == "" {
		return nil, fmt.Errorf("Device name cannot be empty for online packet capture")
	}

	packetCapture := &PacketCapture{
		IsOnline: true,
		Online: OnlineConfig{
			Device:         device,
			SnapshotLength: snapshotLength,
			Promiscuous:    promiscuous,
		},
		Logger: logger.With("module", "online_capture"),
	}

	err := packetCapture.setup()
	if err != nil {
		return nil, err
	}

	return packetCapture, nil
}

/*
Creates online pacet capture using given parameters
*/
func CreateOfflinePacketCapture(filePath string, logger *slog.Logger) (*PacketCapture, error) {
	if filePath == "" {
		return nil, fmt.Errorf("File path cannot be empty")
	}

	packetCapture := &PacketCapture{
		IsOnline: false,
		Offline: OfflineConfig{
			FilePath: filePath,
		},
		Logger: logger.With("module", "offline_capture"),
	}

	err := packetCapture.setup()
	if err != nil {
		return nil, err
	}

	return packetCapture, nil
}

/*
Internal setup function for Create{Online, Offline}PacketCapture
*/
func (p *PacketCapture) setup() error {
	var err error

	if p.IsOnline {
		p.handle, err = pcap.OpenLive(
			p.Online.Device,
			p.Online.SnapshotLength,
			p.Online.Promiscuous,
			pcap.BlockForever,
		)
	} else {
		p.handle, err = pcap.OpenOffline(p.Offline.FilePath)
	}

	if err != nil {
		return fmt.Errorf("pcap opening error: %w\n", err)
	}

	if err := p.handle.SetBPFFilter("tcp"); err != nil {
		return fmt.Errorf("bpf filter failed: %w\n", err)
	}

	p.PacketSource = gopacket.NewPacketSource(p.handle, p.handle.LinkType())
	return nil
}

/*
Closes the handle for resource free

Call defer p.Close()
*/
func (p *PacketCapture) Close() {
	if p.handle != nil {
		p.handle.Close()
	}
}

/*
# Stream Factory for creation of Stream for new TCP connection
  - Engine - Engine for detection of malicious packets
*/
type NIDSStreamFactory struct {
	Logger *slog.Logger
	Engine *detector.Engine
}

/*
# Contains all information about a current stream of packets
  - network, transport - Layer information of the packet stream
  - reader - Used to read the data from the stream
*/
type NIDSStream struct {
	network, transport *gopacket.Flow
	reader             *tcpreader.ReaderStream
	Logger             *slog.Logger
}

func (str *NIDSStream) Reassembled(ra []tcpassembly.Reassembly) {
	str.reader.Reassembled(ra)
}

func (str *NIDSStream) ReassemblyComplete() {
	str.reader.ReassemblyComplete()
}

/*
Creates a new Stream - Called automatically by TCPAssembly
*/
func (sf *NIDSStreamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	connLogger := sf.Logger.With(
		"NetFlow", netFlow.String(),
		"TcpFlow", tcpFlow.String(),
	)

	reader := tcpreader.NewReaderStream()
	stream := NIDSStream{
		reader:    &reader,
		Logger:    connLogger.With("module", "stream"),
		network:   &netFlow,
		transport: &tcpFlow,
	}

	go sf.Engine.Detect(netFlow, tcpFlow, bufio.NewReader(stream.reader), connLogger.With("module", "detector"))

	connLogger.Info("New stream detected")
	return &stream
}

/*
Start processing packets(reassembly and analysis) using a given engine
*/
func (p *PacketCapture) StartProcessing(engine *detector.Engine) {
	streamFactory := &NIDSStreamFactory{Logger: p.Logger.With("module", "stream_factory"), Engine: engine}
	streamPool := tcpassembly.NewStreamPool(streamFactory)

	assembler := tcpassembly.NewAssembler(streamPool)
	assembler.AssemblerOptions.MaxBufferedPagesPerConnection = 10
	assembler.AssemblerOptions.MaxBufferedPagesTotal = 20000

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	packets := p.PacketSource.Packets()

	for {
		select {
		case packet, ok := <-packets:
			if !ok {
				return
			}

			netLayer := packet.NetworkLayer()
			if netLayer == nil {
				continue
			}

			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer == nil {
				continue
			}

			tcp := tcpLayer.(*layers.TCP)
			assembler.AssembleWithTimestamp(
				netLayer.NetworkFlow(),
				tcp,
				packet.Metadata().Timestamp,
			)

		// Flush the older packets to free memory
		case <-ticker.C:
			cutoff := time.Now().Add(-30 * time.Second)
			assembler.FlushOlderThan(cutoff)
		}
	}
}
