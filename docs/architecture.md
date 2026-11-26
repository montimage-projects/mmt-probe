# Architecture

This document describes the internal architecture of MMT-Probe.

## Process Model

MMT-Probe consists of 3 processes:

- **Monitor process** -- The root process. It creates the two children processes and monitors them: it recreates a child if it has crashed.
- **Processing process** -- The main processing. It performs packet capture, DPI/LPI analysis, and report generation.
- **Control process** -- Optional (requires `DYNAMIC_CONFIG_MODULE`). It opens a UNIX domain socket to listen for control commands. After validation, commands are forwarded to the processing process and the monitor process.

```mermaid
graph LR
    subgraph MMT-Probe
        Monitor["Monitor Process<br/>(root)"]
        Processing["Processing Process<br/>(main)"]
        Control["Control Process<br/>(optional)"]
    end

    NIC["NIC / PCAP"] -->|traffic| Processing
    Processing -->|reports| Output["Files / MQTT / Kafka<br/>Redis / MongoDB / Socket"]
    Monitor -->|create / restart| Processing
    Monitor -->|create / restart| Control
    Processing -->|die| Monitor
    Control -->|die| Monitor
    Socket["UNIX Socket"] -->|commands| Control
    Control -->|responses| Socket
```

```
          +----------------------------------------------------------------------------------+
          |                                   +-------------+                                |
          |                                  /             /|                                |
- NIC     |          +------------+         +-------------+ |        +----------+            |
- pcap    | traffic  |            |  create |             | | create |          |   commands |     +--------+
==========|=========>| processing |<--------| monitoring  |--------->| control  |<===========|=====|        |
          | reports  |   proc.    | die     |    proc.    | |    die |  proc.   | responses  |     |  UNIX  |
<=========|==========|            |-------->|             |<---------|          |============|====>| socket |
- files   |          |            |         |             |/         |          |            |     |        |
- redis   |          +------------+         +-------------+          +----------+            |     +--------+
- mongodb |                                                                                  |
- socket  +----------------------------------------------------------------------------------+
- kafka
```

## Processing Pipeline

Within the processing process, packets flow through a multi-threaded pipeline:

```mermaid
graph TD
    Capture["Packet Capture<br/>(libpcap or DPDK)"] --> Dispatch["Packet Dispatcher<br/>(main thread)"]
    Dispatch --> W1["Worker Thread 1"]
    Dispatch --> W2["Worker Thread 2"]
    Dispatch --> WN["Worker Thread N"]

    W1 --> DPI1["DPI / LPI Analysis"]
    W2 --> DPI2["DPI / LPI Analysis"]
    WN --> DPIN["DPI / LPI Analysis"]

    DPI1 --> Reports["Report Generation"]
    DPI2 --> Reports
    DPIN --> Reports

    Reports --> File["File Output"]
    Reports --> MQTT["MQTT"]
    Reports --> Kafka["Kafka"]
    Reports --> Redis["Redis"]
    Reports --> MongoDB["MongoDB"]
    Reports --> UDPSocket["UDP Socket"]
```

1. **Packet Capture** -- Reads packets from a NIC (libpcap/DPDK) or PCAP file
2. **Dispatcher** -- The main thread dispatches packets to worker threads (when `nb-thread > 0`)
3. **Worker Threads** -- Each worker runs independently with its own MMT-DPI handler
4. **DPI/LPI Analysis** -- Deep or Light packet inspection classifies protocols and extracts attributes
5. **Report Generation** -- Session reports, event reports, and security alerts are generated
6. **Output Channels** -- Reports are written to one or more configured output channels

## Shutdown and exit statuses

SIGINT and SIGTERM stop the probe gracefully: the processing child breaks
its capture loop, then drains - workers flush their sessions, the
security engine is unregistered, output files are flushed and closed
(each sampled file gets its `.sem` marker) and the final statistics are
logged. A repeat of the signal that armed the shutdown is a no-op: a
group-wide Ctrl+C or `systemctl stop` (`KillMode=control-group`) reaches
the child both directly and through the monitor's forward, and neither
repeat is allowed to cut the drain short. A *different* second signal
(e.g., SIGTERM while handling SIGINT) remains the hard exit: it exits
the child immediately. The monitor has no grace timer of its own - it
blocks in `waitpid` while the child drains - so a stuck drain is
bounded externally, e.g. by systemd `TimeoutStopSec` or the SIGKILL of
`docker stop`.

The processing child reports its fate to the monitor through its exit
status:

| Child exit status | Meaning | Monitor reaction |
|-------------------|---------|------------------|
| 0 | clean shutdown (SIGINT/SIGTERM handled) | stops the probe, exits 0 |
| 1 (`EXIT_TOBE_RESTARTED`) | crash or restart request | recreates the child |
| 3 (`EXIT_STATUS_NO_RESTART`) | start-up/configuration refusal | stops the whole probe, exits 3 |
| death by SIGINT/SIGTERM | the shutdown that was asked for | exits 0 |
| death by another signal | crash | recreates the child |

Refused configurations - an unreadable or invalid configuration file, a
rejected `-X` override, a failed `conf_validate` - always report status
3, matching `RestartPreventExitStatus=3` in the shipped
`mmt-probe.service`: the service stops instead of restarting forever on a
configuration that cannot work. Real crashes still die by their signal
(139 for SIGSEGV, 134 for SIGABRT as seen from a shell).

## Module Architecture

MMT-Probe uses a modular build system. Modules are compiled conditionally based on build flags:

| Module | Build Flag | Description |
|--------|-----------|-------------|
| DPI Reports | (always on) | Deep packet inspection and session/event reporting |
| LPI | (always on) | Light packet inspection for DDoS resilience |
| PCAP Capture | (default) | Packet capture via libpcap |
| DPDK Capture | `DPDK_CAPTURE` | High-performance packet capture via DPDK |
| Security | `SECURITY_MODULE` | Security rule engine (requires MMT-Security) |
| Kafka Output | `KAFKA_MODULE` | Report output to Apache Kafka |
| MQTT Output | `MQTT_MODULE` | Report output to MQTT broker |
| Redis Output | `REDIS_MODULE` | Report output to Redis |
| MongoDB Output | `MONGODB_MODULE` | Report output to MongoDB |
| Socket Output | `SOCKET_MODULE` | Report output to TCP/UDP/UNIX sockets |
| PCAP Dump | `PCAP_DUMP_MODULE` | Dump packets to PCAP files |
| Dynamic Config | `DYNAMIC_CONFIG_MODULE` | Runtime reconfiguration via UNIX socket |
| TCP Reassembly | `TCP_REASSEMBLY_MODULE` | TCP stream reassembly |
| HTTP Reconstruct | `HTTP_RECONSTRUCT_MODULE` | HTTP payload reconstruction |
| FTP Reconstruct | `FTP_RECONSTRUCT_MODULE` | FTP payload reconstruction |
| License | `LICENSE_MODULE` | License key validation |
| NETCONF | `NETCONF_MODULE` | Reconfiguration via NETCONF protocol |
| QoS | `QOS_MODULE` | Response time and transfer time metrics |

## Source Code Layout

```
src/
├── main.c                    # Entry point, process forking, signal handling
├── configure.c/h             # Configuration file parsing (libconfuse)
├── configure_override.c/h    # Runtime -X parameter overrides
├── worker.c/h                # Worker thread lifecycle
├── context.h                 # Global probe context and shared state
├── lib/                      # Utility libraries
│   ├── log.h                 # Logging macros (syslog)
│   ├── malloc.h              # Safe memory allocation wrappers
│   ├── memory.h              # Memory pool management
│   ├── hash.c/h              # Hash functions
│   ├── string_builder.h      # CSV/report string construction
│   ├── system_info.c/h       # CPU and memory statistics
│   ├── version.c/h           # Version information
│   ├── ms_timer.h            # Millisecond timer for periodic flushing
│   └── ...
└── modules/
    ├── dpi/                   # Deep packet inspection
    │   ├── report/            # Session, event, query reports
    │   ├── reconstruct/       # HTTP/FTP payload reconstruction
    │   ├── reassembly/        # TCP reassembly
    │   └── pcap_dump/         # Packet dump to PCAP
    ├── lpi/                   # Light packet inspection
    ├── output/                # Output channel implementations
    │   ├── file/              # File output (CSV)
    │   ├── kafka/             # Kafka producer
    │   ├── mqtt/              # MQTT publisher
    │   ├── redis/             # Redis output
    │   ├── mongodb/           # MongoDB output
    │   └── socket/            # TCP/UDP/UNIX socket output
    ├── security/              # Security rule engine integration
    ├── packet_capture/
    │   ├── pcap/              # libpcap capture
    │   └── dpdk/              # DPDK capture
    ├── dynamic_conf/          # Dynamic reconfiguration
    ├── license/               # License validation
    └── routine/               # Background periodic tasks
```

## Data Flow

```mermaid
graph LR
    subgraph Input
        NIC[Network Interface]
        PCAP[PCAP File]
    end

    subgraph Processing
        DPI[MMT-DPI Library]
        LPI[Light Packet Inspection]
        SEC[Security Engine]
    end

    subgraph Reports
        SR[Session Reports]
        ER[Event Reports]
        SA[Security Alerts]
        ST[Statistics]
    end

    NIC --> DPI
    PCAP --> DPI
    NIC --> LPI
    DPI --> SR
    DPI --> ER
    DPI --> SEC --> SA
    DPI --> ST
    LPI --> ST
```

## Key Design Decisions

- **Multi-process for resilience** -- The monitor process restarts crashed children automatically, ensuring high availability
- **Multi-threaded workers** -- Packets are dispatched across N worker threads for parallel DPI processing
- **LPI for DDoS resilience** -- Light packet inspection processes packets quickly when DPI would be overwhelmed by attack traffic
- **Modular build** -- Only compile what you need, reducing binary size and dependencies
- **Output abstraction** -- All output channels implement a common interface, allowing reports to be sent to multiple destinations simultaneously
