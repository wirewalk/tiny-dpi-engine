# tiny-dpi-engine

A lightweight Deep Packet Inspection engine written in C11. Captures network traffic, parses packets, classifies protocols using signature matching (Aho-Corasick algorithm) and port-based heuristics, and tracks connection flows in real time.

## Architecture

```
Capture (libpcap) → Parse (Ethernet/IP/TCP/UDP) → Match (Aho-Corasick) → Classify → Flow Table
```

**Components:**

| Component | File | Description |
|-----------|------|-------------|
| Packet parser | `src/packet.c` | Ethernet (including 802.1Q VLAN), IPv4, TCP, UDP header parsing |
| Signature DB | `src/signatures.c` | Loads protocol signatures from text files (`PROTO: pattern`) |
| Aho-Corasick | `src/aho_corasick.c` | O(n) multi-pattern matching with failure links |
| Classifier | `src/classify.c` | 3-stage: payload inspection → signature match → port fallback |
| Flow tracker | `src/flow.c` | Hash table with 5-tuple canonicalization, bidirectional aggregation |
| Capture | `src/capture.c` | libpcap live capture and offline pcap file reading |
| Statistics | `src/stats.c` | Per-protocol counters, classification ratio |

## Build

```bash
make                    # build (auto-detects libpcap)
sudo apt install libpcap-dev   # Debian/Ubuntu — needed for live capture
make test               # build + run unit tests
```

Without libpcap, the engine builds with stubs — packet parsing, classification, and flow tracking work, but live capture is disabled.

## Usage

```bash
# Live capture from interface (requires root/libpcap)
sudo ./tiny-dpi-engine -i eth0 -n 1000

# Read from pcap file
./tiny-dpi-engine -r capture.pcap

# With custom signatures and BPF filter
./tiny-dpi-engine -i any -f "port 53 or port 80" -s my_sigs.sig -n 5000

# Options
-i, --iface IFACE    Network interface (default: auto-detect)
-r, --read FILE      Read from pcap file instead of live capture
-s, --sigs FILE      Signature database (default: signatures/default.sig)
-f, --filter FILTER  BPF filter expression
-n, --count N        Capture N packets then stop (0 = unlimited)
-t, --timeout SEC    Capture timeout
-v, --verbose        Verbose output
-h, --help           Show help
```

## Signature Format

```
# Comment lines start with #
PROTOCOL: pattern_string

HTTP: GET 
HTTP: POST 
SSH: SSH-2.0
TLS: \x16\x03\x01
SIP: INVITE 
RTP: (detected by header structure)
```

Supported protocols: HTTP, HTTPS, DNS, SSH, FTP, SMTP, RTP, SIP, RTCP, QUIC, DHCP, NTP, ICMP, TLS.

## Classification Strategy

1. **Stateful flow tracking** — each connection is tracked by 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol). Once classified, all subsequent packets inherit the classification.

2. **Payload inspection** — checks packet payload for known patterns:
   - Plaintext protocols: HTTP methods, SSH banner, SIP commands, FTP responses
   - Binary protocols: TLS record layer (0x16 0x03 xx), RTP header (version 2, valid PT)
   - Aho-Corasick signature match against loaded database

3. **Port fallback** — if payload inspection fails, classifies by well-known port numbers (80=HTTP, 443=HTTPS, 53=DNS, 22=SSH, etc.)

## Performance Notes

- Aho-Corasick provides O(n) matching regardless of number of signatures
- Flow table uses open-addressing hash table (65537 buckets, ~1M flow limit)
- Zero-copy packet parsing — all operations on raw buffer pointers, no memcpy
- Canonical 5-tuple ensures bidirectional flows share one entry

## License

MIT
