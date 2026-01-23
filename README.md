# Network Intrusion Detection System (NIDS)

A minimal network intrusion detection system implemented in Go.

Quick run (requires sudo for live capture):
- Run: ./run.sh
- Or build and run: go build -o nids ./cmd/nids && sudo ./nids

Project structure
- cmd/                      — CLI entrypoints
  - nids/                   — main program
- internal/
  - alert /                 - sends alerts to user if required
  - capture/                — packet capture, assembly and stream management
  - detector/               — detection engine and signature logic
- data/                     — sample .pcap files (not committed)
- logs/                     — runtime logs (nids.log)
- run.sh                    — convenience runner for development
- LICENSE                   — project license
- todo.md                   — development notes and assumptions


Notes
- The project currently captures TCP only (BPF: "tcp").
- For offline testing, use CreateOfflinePacketCapture with a .pcap file.
- Logs are JSON by default (nids.log). You can switch handler in cmd/nids/main.go.
- See TODOs in todo.md for assumptions and next tasks.

License
- MIT (see LICENSE)
