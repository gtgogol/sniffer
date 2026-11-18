# AGENTS.md — sniffer

Instructions for the AI agent implementing this project. Read this file at the start of every session, then `PLAN.md`.

## What we are building

`sniffer` is a **Python** command-line utility for Linux that captures network traffic and:
- writes it to a valid **pcap** file (classic libpcap format, not pcapng);
- shows packets in the terminal in real time: a one-line summary plus, with a flag, a hex/ASCII dump;
- parses **Ethernet**, **IPv4**, **IPv6**, **TCP**, and **UDP** headers;
- supports simple filtering (protocol, IP, port).

Only Linux is supported.

## Technologies and constraints

- **Python 3.10+**, standard library only at runtime: `socket`, `struct`, `argparse`, `signal`, `time`, `ipaddress`, `select`.
- Capture: **raw socket** `socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))` (ETH_P_ALL). **Do not use** scapy, dpkt, pyshark, pypcap, or similar libraries for capturing, parsing, or writing: implement everything yourself with `struct`. These libraries, as well as `tcpdump`/`tshark`, are allowed only in tests to verify results.
- Development tools: `pytest` for tests, `ruff` for linting, `mypy` for type checking (optional, but code must have type annotations).
- Capturing requires root or `CAP_NET_RAW`. On `PermissionError` the utility prints a clear message with a hint: run it with `sudo` (for example, `sudo python3 -m sniffer ...`).
- Running: `python3 -m sniffer` from the repository root. Development tools are installed manually: `pip install pytest ruff`.

## Repository layout

```
sniffer/
├── AGENTS.md
├── PLAN.md
├── README.md
├── sniffer/
│   ├── __init__.py
│   ├── __main__.py      # python -m sniffer
│   ├── cli.py           # argparse, main(), signals, main loop
│   ├── capture.py       # AF_PACKET socket, bind to interface, promisc
│   ├── pcap_writer.py   # pcap global header and records
│   ├── parse.py         # Ethernet/VLAN/IPv4/IPv6/TCP/UDP parsing into dataclasses
│   ├── filter.py        # simple filter
│   └── output.py        # one-line output and hex dump
└── tests/
    ├── conftest.py
    ├── packets.py         # prepared bytes of test packets
    ├── test_parse.py
    ├── test_pcap_writer.py
    ├── test_filter.py
    ├── test_output.py
    └── test_integration.py  # needs root; marked @pytest.mark.root and skipped without privileges
```

## Command-line interface

```
python3 -m sniffer [-i IFACE] [-w FILE.pcap] [-c COUNT] [-s SNAPLEN] [-p] [-x] [-q] [-f FILTER]
```

| Flag | Meaning |
|---|---|
| `-i, --interface` | interface; defaults to all interfaces (socket not bound) |
| `-w, --write` | pcap file to write; without it, output to the screen only |
| `-c, --count` | stop after N packets that passed the filter |
| `-s, --snaplen` | maximum stored length of each packet, default 65535 |
| `-p, --promisc` | enable promiscuous mode |
| `-x, --hex` | print a hex/ASCII dump of each packet |
| `-q, --quiet` | do not print packets (only write to file and final statistics) |
| `-f, --filter` | simple filter, see below |
| `-h, --help` | help |

A filter is an expression of conditions joined by `and`: `tcp`, `udp`, `ip4`, `ip6`, `host ADDR`, `src host ADDR`, `dst host ADDR`, `port N`, `src port N`, `dst port N` (IPv4 and IPv6 addresses, parsed with `ipaddress`). Example: `-f "tcp and port 443 and host 10.0.0.1"`. Support for `or`/`not`/parentheses is optional and left as a later extension. The filter applies both to screen output and to the file.

Output line format:
```
12:34:56.789012 eth0 IPv4 TCP 192.168.1.5:51234 -> 93.184.216.34:443 [SYN,ACK] len=74
```

On `Ctrl+C` (SIGINT) and SIGTERM the utility closes the file cleanly and prints statistics: captured, passed the filter, written. No stack trace on Ctrl+C.

## pcap format (required details)

- Global header, 24 bytes: `struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, snaplen, 1)` — microsecond magic, version 2.4, thiszone 0, sigfigs 0, snaplen, network = 1 (LINKTYPE_ETHERNET). Byte order is fixed little-endian (`<`).
- Record: `struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)`, followed by exactly `incl_len` bytes; `incl_len = min(len(data), snaplen)`.
- The timestamp is taken right after `recvfrom` with `time.time_ns()` and split into seconds and microseconds using integer arithmetic (no float error).
- The file is opened in binary mode; call `flush()` after every record so the file stays valid even after a crash (a buffering flag may be added later).
- `recvfrom` on AF_PACKET returns the address `(ifname, proto, pkttype, hatype, addr)`. When writing to the file, skip packets whose `hatype` is neither `ARPHRD_ETHER` (1) nor `ARPHRD_LOOPBACK` (772), with one warning per interface.
- On `lo` every packet arrives twice: drop duplicates with `pkttype == PACKET_OUTGOING` (4) on loopback.

## Parsing requirements

- Work with `bytes`/`memoryview`. Before every `struct.unpack_from`, check that enough data remains. A truncated or malformed packet must not raise an exception to the caller; it is marked with `truncated`/`malformed` flags and still written to the pcap.
- The parse result is a `@dataclass(slots=True) PacketInfo` with L2/L3/L4 fields (`None` if a layer is absent).
- Ethernet: MAC addresses, EtherType; support one 802.1Q VLAN tag (`0x8100`).
- IPv4: version, IHL (including options), total length, TTL, protocol, addresses; fragments (offset ≠ 0) are not parsed at L4.
- IPv6: fixed header plus skipping the Hop-by-Hop (0), Routing (43), Fragment (44), and Destination Options (60) extension headers up to TCP/UDP.
- TCP: ports, seq/ack, data offset, flags. UDP: ports, length.
- Network byte order: `struct` formats with the `!` prefix. Addresses via `ipaddress.ip_address(bytes)` or `socket.inet_ntop`.

## Performance

Python is slower than C, so:
- no unnecessary copies in the hot loop: `recv_into` into a preallocated `bytearray` and `memoryview`;
- precompiled module-level `struct.Struct` objects;
- parsing runs only when needed (output enabled or a filter set); with `-q -w` and no filter, the packet is written straight to the file;
- terminal output must not block capture for long: line-buffered `sys.stdout`.

## Rules for the agent

1. Follow `PLAN.md` strictly, stage by stage. After each stage: `ruff check .` with no errors, `pytest` green, mark the items in `PLAN.md` as done (`[x]`).
2. Small commits with clear messages: `parse: add IPv6 extension header skipping`.
3. Write parsing, filtering, output, and pcap writing as pure functions over `bytes` so they can be tested without root or network. The socket is used only in `capture.py`.
4. Do not add runtime dependencies or change the CLI without recording it in the "Decisions" section of `PLAN.md`.
5. If something cannot be verified in the sandbox (no root, no network), still write the test and state clearly in your report that it was not run.
6. Never make up test results: quote the real command output in your report.
7. Code, docstrings, and comments in English, `README.md` in Russian. Type annotations on all public functions.
8. If the Ponytail skill (or any other style or minimal-code ruleset) is active, `AGENTS.md` and `PLAN.md` take precedence over it. Use Ponytail to avoid unnecessary code and dependencies and for `/ponytail-review` or `/ponytail-audit` after a stage, but never cut functionality listed in `PLAN.md` or tests required by the Definition of done (including the fuzz test and the benchmark). Never replace or overwrite this `AGENTS.md` with Ponytail's own `AGENTS.md`.

## Definition of done

- `pytest` passes (root tests are skipped without privileges and pass under `sudo`).
- `ruff check .` reports no errors.
- `sudo python3 -m sniffer -i eth0 -w out.pcap -c 50` creates a file that `tcpdump -r out.pcap` and `tshark -r out.pcap`/Wireshark read without errors, and the packet count matches.
- Real-time screen output; the filter works for both the screen and the file.
- None of the random buffers in the fuzz test cause an unhandled exception.
- `README.md` covers installation, privileges, flags, and examples.
