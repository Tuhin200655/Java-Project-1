# High-Performance Deep Packet Inspection (DPI) & Traffic Filtering Engine

[![Java](https://img.shields.io/badge/Java-17%2B-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white)](https://openjdk.org/)
[![Architecture](https://img.shields.io/badge/Architecture-Multi--Stage%20Pipelined-00599C?style=for-the-badge)](https://github.com)
[![Protocol Support](https://img.shields.io/badge/Protocols-IPv4%20%7C%20TCP%20%7C%20UDP%20%7C%20TLS%20%7C%20HTTP%20%7C%20DNS-4B32C3?style=for-the-badge)](https://github.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)

A carrier-grade, highly concurrent, multi-threaded **Deep Packet Inspection (DPI)** and stateful traffic filtering system engineered in **Java 17+**. Originally ported and re-architected from high-performance C++ networking designs, this engine provides sub-microsecond classification, real-time Layer 7 payload dissection (TLS SNI, HTTP Host, DNS queries), multi-dimensional rule-based policy enforcement, and lock-free connection tracking across hundreds of thousands of concurrent network flows without external third-party dependencies.

---

## Table of Contents

1. [Executive Summary & Core Highlights](#executive-summary--core-highlights)
2. [End-to-End System Architecture](#end-to-end-system-architecture)
   - [Pipelined Processing Stages](#pipelined-processing-stages)
   - [Consistent 5-Tuple Hashing & Thread Pinning](#consistent-5-tuple-hashing--thread-pinning)
   - [Lock-Free Connection Tracking](#lock-free-connection-tracking)
   - [Producer-Consumer Queueing with Backpressure](#producer-consumer-queueing-with-backpressure)
3. [Deep Packet Inspection (DPI) Engine](#deep-packet-inspection-dpi-engine)
   - [Layer 2 to Layer 4 Binary Parsing](#layer-2-to-layer-4-binary-parsing)
   - [TLS 1.2 / 1.3 Client Hello SNI Extraction](#tls-12--13-client-hello-sni-extraction)
   - [HTTP/1.x Host Header Parsing](#http1x-host-header-parsing)
   - [DNS Query Extraction (RFC 1035 Wire Format)](#dns-query-extraction-rfc-1035-wire-format)
   - [Application Signature Taxonomy](#application-signature-taxonomy)
4. [Stateful Connection Tracking & TCP State Machine](#stateful-connection-tracking--tcp-state-machine)
5. [Rule Management & Policy Enforcement](#rule-management--policy-enforcement)
   - [Multi-Domain Rule Engine](#multi-domain-rule-engine)
   - [Concurrent Read-Write Locking](#concurrent-read-write-locking)
   - [Rule Configuration File Syntax](#rule-configuration-file-syntax)
6. [Binary PCAP I/O Engine](#binary-pcap-io-engine)
7. [Directory & Package Structure](#directory--package-structure)
8. [Build & Installation Guide](#build--installation-guide)
9. [CLI Usage & Configuration Options](#cli-usage--configuration-options)
10. [Execution Demonstration & Reporting](#execution-demonstration--reporting)
11. [Performance Optimizations & Systems Engineering](#performance-optimizations--systems-engineering)
12. [Edge Cases & Technical Considerations](#edge-cases--technical-considerations)

---

## Executive Summary & Core Highlights

In modern network infrastructure, line-rate Deep Packet Inspection requires deterministic packet distribution, minimal lock contention, zero-copy memory patterns, and accurate Layer 7 protocol extraction. This project demonstrates an enterprise-grade packet processing architecture designed to parse raw Ethernet frames, reconstruct transport-layer state machines, inspect encrypted and plain text application payloads, and apply line-rate policy drops.

### Key Capabilities:
- **Zero Third-Party Runtime Dependencies**: Implemented strictly with standard **Java 17 (NIO, Concurrency, Bit Manipulation)** for complete portability, zero runtime bloat, and minimal attack surface.
- **Hierarchical Load Balancing (LB $\rightarrow$ FP)**: Two-tier producer-consumer distribution topology eliminating cache invalidation and thread thrashing.
- **Deterministic 5-Tuple Affinity**: Implements a Boost-style golden-ratio hash combiner (`0x9e3779b9`) mapping symmetric IP/Port pairs to dedicated **Fast Path (FP)** processing threads.
- **Lock-Free Flow Tables**: Because flows are hash-pinned to designated FP threads, per-worker connection tables operate lock-free with zero mutex overhead.
- **Layer 7 Dissectors**:
  - **TLS SNI Dissector**: Traverses TLS Record Headers, Handshake structures, Session IDs, Cipher Suites, and Extension blocks to extract the Server Name Indication.
  - **HTTP Host Dissector**: Fast method identification (`GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, `PATCH`) with case-insensitive host extraction and port stripping.
  - **DNS Dissector**: Decodes uncompressed RFC 1035 wire labels from UDP datagrams.
- **High-Granularity Access Control**: Drop or forward packets based on Source IP, Layer 4 Destination Port, Classified Application Type, or Domain name patterns (including wildcard subdomains such as `*.tiktok.com`).
- **Comprehensive Observability**: Real-time atomic counters and diagnostic reporting showing drop rates, application distributions (with ASCII histogram generation), and connection lifecycles.

---

## End-to-End System Architecture

```
                                  ┌─────────────────────────────┐
                                  │     Raw PCAP File Input     │
                                  └──────────────┬──────────────┘
                                                 │
                                                 ▼
                                  ┌─────────────────────────────┐
                                  │   PcapReader Worker Thread  │
                                  │  - Endianness Auto-Detect   │
                                  │  - Ethernet/IPv4 Decapsulate│
                                  └──────────────┬──────────────┘
                                                 │
                                       hash(5-Tuple) % NumLBs
                                                 │
                        ┌────────────────────────┴────────────────────────┐
                        ▼                                                 ▼
         ┌─────────────────────────────┐                   ┌─────────────────────────────┐
         │     LB-0 Worker Thread      │                   │     LB-1 Worker Thread      │
         │ (ThreadSafeQueue: cap 10000)│                   │ (ThreadSafeQueue: cap 10000)│
         └──────────────┬──────────────┘                   └──────────────┬──────────────┘
                        │                                                 │
              hash(5-Tuple) % FpsPerLb                          hash(5-Tuple) % FpsPerLb
                        │                                                 │
            ┌───────────┴───────────┐                         ┌───────────┴───────────┐
            ▼                       ▼                         ▼                       ▼
     ┌──────────────┐        ┌──────────────┐          ┌──────────────┐        ┌──────────────┐
     │  FP-0 Worker │        │  FP-1 Worker │          │  FP-2 Worker │        │  FP-3 Worker │
     │  - ConnTable │        │  - ConnTable │          │  - ConnTable │        │  - ConnTable │
     │  - TCP FSM   │        │  - TCP FSM   │          │  - TCP FSM   │        │  - TCP FSM   │
     │  - DPI Layer │        │  - DPI Layer │          │  - DPI Layer │        │  - DPI Layer │
     │  - Rule Match│        │  - Rule Match│          │  - Rule Match│        │  - Rule Match│
     └──────┬───────┘        └──────┬───────┘          └──────┬───────┘        └──────┬───────┘
            │                       │                         │                       │
      [FORWARD / DROP]        [FORWARD / DROP]          [FORWARD / DROP]        [FORWARD / DROP]
            │                       │                         │                       │
            └───────────────────────┴────────────┬────────────┴───────────────────────┘
                                                 │
                                           FORWARD Packets
                                                 │
                                                 ▼
                                  ┌─────────────────────────────┐
                                  │   Output ThreadSafeQueue    │
                                  │       (Capacity: 10,000)    │
                                  └──────────────┬──────────────┘
                                                 │
                                                 ▼
                                  ┌─────────────────────────────┐
                                  │ OutputWriter Thread (PCAP)  │
                                  └─────────────────────────────┘
```

### Pipelined Processing Stages

1. **Ingestion & Decapsulation (PcapReader Thread)**:
   - Reads the 24-byte PCAP Global Header, negotiates endianness, and validates link-layer framing (Ethernet II).
   - Iterates through 16-byte PCAP packet headers, slices raw frames, validates IPv4 boundaries, and constructs lightweight `PacketJob` descriptors.
   - Calculates the primary 5-tuple hash and deposits the job into the appropriate Load Balancer's `ThreadSafeQueue`.

2. **Load Balancing Tier (`LbManager` & `LoadBalancer`)**:
   - Decouples disk reading speed from inspection processing.
   - Computes sub-hashes targeting specific Fast Path processors assigned to that LB partition (`hash % FPsPerLb`).
   - Prevents queue congestion through non-busy-waiting synchronization.

3. **Fast Path Inspection Tier (`FpManager` & `FastPathProcessor`)**:
   - Executes the core DPI pipeline on dedicated threads (`FP-0`, `FP-1`, ...).
   - Maintains stateful connection tables, updates TCP handshake state machines, triggers protocol extractors on payload segments, and checks blacklists.
   - Emits routing verdicts (`FORWARD` or `DROP`).

4. **Serialized Egress (OutputWriter Thread)**:
   - Collects forwarded frames from an aggregated output queue.
   - Synchronously writes original frame timestamps and payloads back to a valid PCAP file, ensuring standard pcap integrity for downstream consumption (Wireshark, Zeek, Suricata).

---

### Consistent 5-Tuple Hashing & Thread Pinning

To maintain deterministic packet ordering and prevent multi-threaded race conditions during connection tracking, packets belonging to the same network flow must always be processed by the exact same Fast Path core.

The system uses a Boost-inspired golden-ratio multiplier hash combining source/destination IP addresses, Layer 4 ports, and protocol identifier:

```java
// FiveTuple.java
@Override
public int hashCode() {
    long h = 0;
    h ^= Long.hashCode(srcIp)   + 0x9e3779b9L + (h << 6) + (h >> 2);
    h ^= Long.hashCode(dstIp)   + 0x9e3779b9L + (h << 6) + (h >> 2);
    h ^= Integer.hashCode(srcPort)  + 0x9e3779b9L + (h << 6) + (h >> 2);
    h ^= Integer.hashCode(dstPort)  + 0x9e3779b9L + (h << 6) + (h >> 2);
    h ^= Integer.hashCode(protocol) + 0x9e3779b9L + (h << 6) + (h >> 2);
    return (int) h;
}
```

- **Mathematical Invariant**: $hash(\text{flow}) \pmod N$ is strictly deterministic.
- **Cache Locality**: Packets for a single connection are repeatedly processed by the same CPU core, maximizing L1/L2 data and instruction cache hits.

---

### Lock-Free Connection Tracking

Standard DPI architectures that use a global synchronized flow table suffer severe mutex contention under multi-gigabit workloads. 

This engine eliminates global locks in the critical path:
- Each `FastPathProcessor` owns an isolated, single-threaded `ConnectionTracker` flow table (`HashMap<FiveTuple, Connection>`).
- Lookups, flow insertions, TCP flag updates, and byte increments happen **without locks or synchronization barriers**.
- Global reporting aggregates statistics safely by combining read-locks during shutdown or report rendering via `GlobalConnectionTable`.

---

### Producer-Consumer Queueing with Backpressure

Inter-thread communication uses `ThreadSafeQueue<T>`, backed by `java.util.concurrent.ArrayBlockingQueue`.

- **Backpressure Protection**: Queues are bounded to 10,000 entries. When workers are saturated, upstream producers yield using timed offerings (`offer(item, 100, TimeUnit.MILLISECONDS)`), preventing uncontrolled heap growth and `OutOfMemoryError`.
- **Clean Shutdown**: A dedicated `AtomicBoolean shutdown` state signals downstream workers to drain remaining items during EOF without leaving lingering threads.

---

## Deep Packet Inspection (DPI) Engine

The engine parses packets from Layer 2 up to Layer 7 without relying on off-the-shelf parsing libraries.

### Layer 2 to Layer 4 Binary Parsing

`PacketParser` validates headers and computes relative offsets directly from `byte[]` arrays:
- **Ethernet II**: Validates 14-byte header, extracts MAC addresses, and verifies EtherType `0x0800` (IPv4).
- **IPv4**:
  - Validates Version ($= 4$) and extracts Internet Header Length (IHL).
  - Dynamically computes variable header length: $\text{HeaderLen} = \text{IHL} \times 4$.
  - Extracts TTL, Layer 4 Protocol (TCP `6`, UDP `17`, ICMP `1`), Source IP, and Destination IP.
- **TCP**:
  - Extracts 16-bit Source/Destination ports, Sequence Numbers, Acknowledgment Numbers.
  - Extracts Data Offset: $\text{TcpHeaderLen} = \text{DataOffset} \times 4$.
  - Extracts Control Flags: `SYN` (0x02), `ACK` (0x10), `FIN` (0x01), `RST` (0x04).
  - Calculates accurate Payload Offset and Length.
- **UDP**:
  - Extracts 8-byte header (Ports, Length, Checksum) and sets payload offset to $\text{transportOffset} + 8$.

---

### TLS 1.2 / 1.3 Client Hello SNI Extraction

`SniExtractor` parses encrypted HTTPS sessions by dissecting the initial plain text TLS Handshake message:

1. **Record Layer Inspection**:
   - Verifies Content Type is Handshake (`0x16`).
   - Verifies TLS Version (`0x0300` to `0x0304` covering SSL 3.0 through TLS 1.3).
   - Validates that Record Length does not exceed available packet bounds.
2. **Handshake Layer Traversal**:
   - Confirms Handshake Type is `Client Hello` (`0x01`).
   - Skips Handshake Length (3 bytes), Client Version (2 bytes), and Client Random (32 bytes).
3. **Variable Structure Stepping**:
   - Reads `Session ID Length` ($L_{\text{session}}$) and skips $1 + L_{\text{session}}$ bytes.
   - Reads `Cipher Suites Length` ($L_{\text{cipher}}$) and skips $2 + L_{\text{cipher}}$ bytes.
   - Reads `Compression Methods Length` ($L_{\text{comp}}$) and skips $1 + L_{\text{comp}}$ bytes.
4. **Extension Block Parsing**:
   - Iterates through extension records until `Extension Type == 0x0000` (Server Name Indication).
   - Confirms Server Name Type is `0x00` (Hostname).
   - Extracts ASCII hostname string directly from payload bytes.

```
+---------------+---------------+---------------+---------------+
| Content: 0x16 | Version (2B)  | Record Length (2 Bytes)       |
+---------------+---------------+---------------+---------------+
| Handshake: 0x1| Length (3B)   | Version (2B)  | Random (32B)  |
+---------------+---------------+---------------+---------------+
| Session ID Len| Session ID ...| Cipher Suites | Compression...|
+---------------+---------------+---------------+---------------+
| Extensions Len| Ext Type 0x00 | Ext Data Len  | SNI List Len  |
+---------------+---------------+---------------+---------------+
| Type: 0x00    | Hostname Len  | Hostname: "www.example.com"  |
+---------------+---------------+---------------+---------------+
```

---

### HTTP/1.x Host Header Parsing

`HttpHostExtractor` inspects unencrypted port 80 traffic:
- **Method Validation**: Fast prefix check against standard HTTP verbs (`GET `, `POST`, `PUT `, `HEAD`, `DELE`, `PATC`, `OPTI`).
- **Header Scanning**: Scans payload bytes for case-insensitive `Host:` or `host:` header.
- **Host Extraction**: Strips leading whitespace, extracts the hostname string until `\r` or `\n`, and strips optional port declarations (e.g., `example.com:8080` $\rightarrow$ `example.com`).

---

### DNS Query Extraction (RFC 1035 Wire Format)

`DnsExtractor` decodes DNS queries over UDP port 53:
- **Header Verification**: Ensures QR bit is `0` (Query) and `QDCOUNT` $\ge 1$.
- **Wire Label Decoding**:
  - Traverses sequential length-prefixed DNS labels (e.g., `\x06google\x03com\x00`).
  - Converts label lengths into dot-delimited string representations (`google.com`).
  - Guards against buffer overflows and DNS compression pointers (`labelLen > 63`).

---

### Application Signature Taxonomy

The `AppClassifier` correlates extracted hostnames and domains against real-world traffic fingerprints:

| Application Category | Fingerprinted Domains / SNI Signatures |
| :--- | :--- |
| **YouTube** | `youtube.com`, `ytimg.com`, `youtu.be`, `yt3.ggpht.com` |
| **Google Services** | `google.com`, `gstatic.com`, `googleapis.com`, `ggpht.com`, `gvt1.com` |
| **Facebook / Meta** | `facebook.com`, `fbcdn.net`, `fb.com`, `fbsbx.com`, `meta.com` |
| **Instagram** | `instagram.com`, `cdninstagram.com` |
| **Twitter / X** | `twitter.com`, `twimg.com`, `x.com`, `t.co` |
| **TikTok** | `tiktok.com`, `tiktokcdn.com`, `musical.ly`, `bytedance.com` |
| **Netflix** | `netflix.com`, `nflxvideo.net`, `nflximg.net` |
| **Amazon / AWS** | `amazon.com`, `amazonaws.com`, `cloudfront.net`, `aws.amazon.com` |
| **Microsoft / Azure** | `microsoft.com`, `msn.com`, `office.com`, `azure.com`, `live.com`, `outlook.com`, `bing.com` |
| **Apple** | `apple.com`, `icloud.com`, `mzstatic.com`, `itunes.com` |
| **WhatsApp** | `whatsapp.com`, `wa.me` |
| **Telegram** | `telegram.org`, `t.me` |
| **Spotify** | `spotify.com`, `scdn.co` |
| **Discord** | `discord.com`, `discordapp.com` |
| **GitHub** | `github.com`, `githubusercontent.com` |
| **Zoom** | `zoom.us` |
| **Cloudflare** | `cloudflare.com` |

---

## Stateful Connection Tracking & TCP State Machine

Each connection flow transitions through a deterministic state machine:

```
  [SYN Received]
        │
        ▼
   ┌─────────┐      [SYN-ACK + ACK]      ┌─────────────┐
   │   NEW   ├──────────────────────────►│ ESTABLISHED │
   └────┬────┘                           └──────┬──────┘
        │                                       │
        │ [Payload Inspected]                   │ [Payload Inspected]
        ▼                                       ▼
 ┌──────────────┐                        ┌──────────────┐
 │  CLASSIFIED  │                        │  CLASSIFIED  │
 └──────┬───────┘                        └──────┬───────┘
        │                                       │
        │ [Rule Violation Matched]              │ [Rule Violation Matched]
        ▼                                       ▼
 ┌──────────────┐                        ┌──────────────┐
 │   BLOCKED    │ (All subsequent packets│   BLOCKED    │
 │ (Action=DROP)│  dropped immediately)  │ (Action=DROP)│
 └──────────────┘                        └──────────────┘
        │                                       │
        │ [FIN / RST Seen]                      │ [FIN / RST Seen]
        ▼                                       ▼
 ┌──────────────┐                        ┌──────────────┐
 │    CLOSED    │                        │    CLOSED    │
 └──────────────┘                        └──────────────┘
```

### Connection State Attributes:
- **5-Tuple Identifier**: Source IP, Destination IP, Source Port, Destination Port, Protocol.
- **Bi-directional Volume Counters**: `packetsIn`, `packetsOut`, `bytesIn`, `bytesOut`.
- **Temporal Tracking**: `firstSeen`, `lastSeen` instants used by stale-connection pruning routines (`cleanupStale(Duration.ofSeconds(300))`).
- **Connection Capacity & LRU Eviction**: Caps max active flows per core (default: 100,000) to protect against memory exhaustion during SYN flood scenarios.

---

## Rule Management & Policy Enforcement

### Multi-Domain Rule Engine

Filtering decisions occur via `RuleManager.shouldBlock(...)`, executing in hierarchical order:

1. **IP Rule Check**: Bitwise matching of source IPv4 against blacklisted 32-bit values.
2. **Port Rule Check**: Destination port matching against prohibited ports.
3. **Application Rule Check**: Prohibits traffic matching classified `AppType` enums.
4. **Domain Rule Check**: Supports both exact domain matching and wildcard patterns (e.g., `*.tiktok.com`, matching any subdomain or base domain).

### Concurrent Read-Write Locking

Rules can be dynamically added, updated, or purged at runtime while worker threads are actively processing traffic. To maintain line-rate throughput:
- Separate `ReentrantReadWriteLock` instances guard each rule dimension (`ipLock`, `appLock`, `domainLock`, `portLock`).
- Worker threads acquire shared **Read Locks** during packet inspection ($O(1)$ lookup without blocking peer threads).
- CLI or administrative mutations acquire exclusive **Write Locks**, ensuring thread-safety without stalling the entire engine.

### Rule Configuration File Syntax

Rule policies can be loaded from and saved to simple declarative text files:

```ini
[BLOCKED_IPS]
192.168.1.100
10.0.0.45

[BLOCKED_APPS]
YOUTUBE
TIKTOK
NETFLIX

[BLOCKED_DOMAINS]
*.facebook.com
doubleclick.net
*.adservice.google.com

[BLOCKED_PORTS]
23
445
```

---

## Binary PCAP I/O Engine

The engine reads and writes standard PCAP format (Libpcap) using pure Java NIO:

- **Global Header Handling**:
  - Automatically identifies byte order by testing magic bytes:
    - `0xa1b2c3d4`: Native Big-Endian.
    - `0xd4c3b2a1`: Little-Endian (automatically swaps `ByteOrder.LITTLE_ENDIAN`).
  - Reads major/minor versions, snaplen (maximum captured length), and data link type (Ethernet `1`).
- **Packet Header & Data Marshalling**:
  - Reads 16-byte record headers (`ts_sec`, `ts_usec`, `incl_len`, `orig_len`).
  - Writes valid filtered PCAP captures, preserving original packet microsecond timestamps.

---

## Directory & Package Structure

```
PacketAnalyzer-Java/
├── pom.xml                                  # Maven project configuration (Java 17+)
├── packet-analyzer.jar                      # Pre-compiled standalone executable binary
├── build.bat                                # Windows build & packaging script
├── README.md                                # Comprehensive project documentation
├── src/main/java/com/dpi/
│   ├── Main.java                            # CLI argument parser & entry point
│   ├── DpiEngine.java                       # Master pipeline coordinator & lifecycle
│   ├── model/
│   │   ├── FiveTuple.java                   # 5-tuple key with Boost-style hash
│   │   ├── AppType.java                     # Enumerated application protocols
│   │   ├── ConnectionState.java             # TCP / flow lifecycle states
│   │   ├── PacketAction.java                # Verdict: FORWARD, DROP, INSPECT
│   │   ├── Connection.java                  # Flow record with statistics & state
│   │   ├── PacketJob.java                   # In-flight packet container & offsets
│   │   └── DpiStats.java                    # Atomic engine-wide throughput metrics
│   ├── pcap/
│   │   ├── PcapGlobalHeader.java            # 24-byte binary PCAP header
│   │   ├── PcapPacketHeader.java            # 16-byte binary packet record header
│   │   ├── RawPacket.java                   # Raw binary frame & metadata container
│   │   └── PcapReader.java                  # Endian-aware stream reader & writer
│   ├── parser/
│   │   └── PacketParser.java                # Zero-copy Ethernet/IP/TCP/UDP decapsulation
│   ├── inspector/
│   │   ├── SniExtractor.java                # TLS 1.2/1.3 Client Hello SNI parser
│   │   ├── HttpHostExtractor.java           # HTTP/1.x method and Host header parser
│   │   └── DnsExtractor.java                # RFC 1035 wire label DNS parser
│   ├── util/
│   │   └── AppClassifier.java               # Domain-to-AppType heuristic matcher
│   ├── tracker/
│   │   ├── ConnectionTracker.java           # Per-core lock-free flow table
│   │   └── GlobalConnectionTable.java       # Aggregated reporting across all cores
│   ├── rules/
│   │   └── RuleManager.java                 # Concurrently guarded filtering policies
│   └── pipeline/
│       ├── ThreadSafeQueue.java             # Non-busy bounded backpressure queue
│       ├── LoadBalancer.java                # Layer 1 hash dispatcher thread
│       ├── LbManager.java                   # Load Balancer pool lifecycle manager
│       ├── FastPathProcessor.java           # Layer 2 Fast Path DPI worker thread
│       └── FpManager.java                   # Fast Path thread pool manager
```

---

## Build & Installation Guide

### Prerequisites
- **Java Development Kit (JDK) 17 or higher** (`java -version`, `javac -version`).
- Optional: **Apache Maven 3.6+** (for standard Maven builds).

### Build Option 1: Standard Maven

```bash
# Clean, compile, and package executable fat JAR
mvn clean package
```
*The resulting binary is output to `target/packet-analyzer-1.0.0.jar`.*

### Build Option 2: Windows Batch Script (`build.bat`)

```cmd
# Runs standard javac compilation and generates packet-analyzer.jar
build.bat
```

### Build Option 3: Direct `javac` Compilation

```bash
# Create binary directory
mkdir bin

# Compile all source files
javac -d bin src/main/java/com/dpi/**/*.java src/main/java/com/dpi/*.java

# Package executable JAR
jar cfe packet-analyzer.jar com.dpi.Main -C bin .
```

---

## CLI Usage & Configuration Options

```bash
java -jar packet-analyzer.jar <input.pcap> <output.pcap> [options]
```

### Positional Arguments
- `<input.pcap>`: Path to the captured source PCAP file.
- `<output.pcap>`: Destination path where permitted (non-dropped) packets will be written.

### Configuration Flags

| Parameter | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `--block-app <name>` | String | — | Prohibit an application (e.g., `YouTube`, `Facebook`, `TikTok`). |
| `--block-ip <ip>` | String | — | Prohibit a source IPv4 address (e.g., `192.168.1.100`). |
| `--block-domain <dom>` | String | — | Prohibit domain or wildcard pattern (e.g., `*.tiktok.com`). |
| `--rules <file>` | String | — | Path to a structured rule configuration file. |
| `--lbs <n>` | Integer | `2` | Number of primary Load Balancer threads. |
| `--fps <n>` | Integer | `2` | Number of Fast Path worker threads per Load Balancer. |
| `--verbose` | Flag | `false` | Enable detailed per-packet processing logs. |
| `--help`, `-h` | Flag | — | Display CLI usage reference. |

---

## Execution Demonstration & Reporting

### Quick Demo (Ready to Run)
Test the engine immediately after cloning using the bundled demo capture and sample rule configuration:

```bash
java -jar packet-analyzer.jar samples/demo.pcap filtered.pcap --rules sample_rules.txt
```

### Example 1: Basic Traffic Analysis
Dissect packets, fingerprint applications, and generate a sanitized output PCAP without drops:

```bash
java -jar packet-analyzer.jar capture.pcap filtered.pcap
```

### Example 2: Target Application Blocking
Block all YouTube and TikTok streaming traffic:

```bash
java -jar packet-analyzer.jar capture.pcap filtered.pcap --block-app YouTube --block-app TikTok
```

### Example 3: Subnet Protection with Wildcard Domain Blocking
Enforce multi-rule filtering using custom thread pooling:

```bash
java -jar packet-analyzer.jar capture.pcap filtered.pcap \
  --block-ip 192.168.1.50 \
  --block-domain *.facebook.com \
  --lbs 4 \
  --fps 4
```

### Sample Engine Diagnostic Output

Upon execution completion, the engine produces structured ASCII diagnostic telemetry:

```
╔══════════════════════════════════════════════════════════════╗
║                    DPI ENGINE v1.0                           ║
║               Deep Packet Inspection System                  ║
╠══════════════════════════════════════════════════════════════╣
║ Configuration:                                               ║
║   Load Balancers:      2                                     ║
║   FPs per LB:          2                                     ║
║   Total FP threads:    4                                     ║
╚══════════════════════════════════════════════════════════════╝

[DPIEngine] Initialized successfully
[FP0] Started
[FP1] Started
[FP2] Started
[FP3] Started
[LB0] Started (serving FP0-FP1)
[LB1] Started (serving FP2-FP3)
[DPIEngine] All threads started
[Reader] Starting packet processing...
[FP0] BLOCKED packet: APP YouTube
[FP2] BLOCKED packet: DOMAIN *.tiktok.com
[Reader] Finished reading 14,820 packets
[DPIEngine] All threads stopped

╔══════════════════════════════════════════════════════════════╗
║                    DPI ENGINE STATISTICS                     ║
╠══════════════════════════════════════════════════════════════╣
║ PACKET STATISTICS                                            ║
║   Total Packets:             14820                           ║
║   Total Bytes:            12548902                           ║
║   TCP Packets:               13910                           ║
║   UDP Packets:                 910                           ║
╠══════════════════════════════════════════════════════════════╣
║ FILTERING STATISTICS                                         ║
║   Forwarded:                 11425                           ║
║   Dropped/Blocked:            3395                           ║
║   Drop Rate:                 22.91%                          ║
╠══════════════════════════════════════════════════════════════╣
║ LOAD BALANCER STATISTICS                                     ║
║   LB Received:               14820                           ║
║   LB Dispatched:             14820                           ║
╠══════════════════════════════════════════════════════════════╣
║ FAST PATH STATISTICS                                         ║
║   FP Processed:              14820                           ║
║   FP Forwarded:              11425                           ║
║   FP Dropped:                 3395                           ║
║   Active Connections:          342                           ║
╚══════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════╗
║                 APPLICATION CLASSIFICATION REPORT            ║
╠══════════════════════════════════════════════════════════════╣
║ Total Connections:             342                           ║
║ Classified:                    318 ( 93.0%)                  ║
║ Unidentified:                   24 (  7.0%)                  ║
╠══════════════════════════════════════════════════════════════╣
║                    APPLICATION DISTRIBUTION                  ║
╠══════════════════════════════════════════════════════════════╣
║ Google                 114  33.3% ######                     ║
║ YouTube                 82  24.0% ####                       ║
║ HTTPS                   45  13.2% ##                         ║
║ Microsoft               31   9.1% #                          ║
║ TikTok                  24   7.0% #                          ║
║ DNS                     12   3.5%                            ║
║ GitHub                  10   2.9%                            ║
║ Unknown                 24   7.0% #                          ║
╚══════════════════════════════════════════════════════════════╝
```

---

## Performance Optimizations & Systems Engineering

1. **Zero-Contention Data Structures**:
   - Isolating connection tables per FP thread removes the synchronization bottleneck commonly observed in naive multi-threaded DPI implementations.
2. **CPU Cache Preservation**:
   - Pinned 5-tuple packet flows guarantee that hot metadata associated with active streams remains in L1/L2 caches of the processing CPU core.
3. **Adaptive Backpressure**:
   - Using bounded `ArrayBlockingQueue` with timed polling prevents thread exhaustion and buffers bursts without unbounded heap growth.
4. **Early Exit Dissection**:
   - As soon as a connection's application identity is classified (e.g., after the initial TLS Client Hello or HTTP GET request), subsequent packets skip deeper Layer 7 inspections, immediately forwarding or dropping based on cached state.

---

## Edge Cases & Technical Considerations

- **Out-of-Order Packets & TCP Reassembly**: The current implementation inspects application payloads that reside within initial transport segments. In enterprise scenarios with heavy packet fragmentation, full TCP stream reassembly (sliding window buffering) is recommended.
- **TLS 1.3 Encrypted Client Hello (ECH)**: As the Internet transitions toward ECH, plain text SNI headers become encrypted. In such environments, DPI systems complement SNI inspection with DNS query correlation (DNS-over-HTTPS inspection) and IP/AS reputation profiling.
- **Zero-Copy Native Acceleration**: For line-rate multi-10Gbps operation, this Java architecture can interface directly with AF_PACKET, DPDK, or PF_RING through modern Java Foreign Function & Memory APIs (Project Panama).

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
