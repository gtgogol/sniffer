# PLAN.md — sniffer (Python)

Stage-by-stage implementation plan. Mark completed items with `[x]`. Every stage ends with a green `ruff check .` and `pytest`.

## Stage 0. Skeleton
- [x] Create the layout from `AGENTS.md` and `__main__.py`.
- [x] `cli.py`: `argparse` with all flags, validation (`--count > 0`, `--snaplen` in the range 1..262144); invalid arguments exit with code 2.
- [x] Check: `python3 -m sniffer -h`; a test for argument parsing.

## Stage 1. Capture via AF_PACKET
- [x] `capture.py`: class `RawCapture(iface: str | None, promisc: bool, snaplen: int)` — a context manager; creates `socket(AF_PACKET, SOCK_RAW, ntohs(ETH_P_ALL))` and, when an interface is given, calls `bind((iface, 0))`.
- [x] Promiscuous mode: `setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, struct.pack("iHH8s", ifindex, PACKET_MR_PROMISC, 0, b""))`, with `ifindex` from `socket.if_nametoindex`.
- [x] Method `read() -> RawPacket | None` (data, `time_ns` timestamp, ifname, pkttype, hatype); uses `select`/`settimeout` so the loop can react to a stop request.
- [x] Clear errors: `PermissionError` (no root), `OSError` for a nonexistent interface.
- [x] SIGINT/SIGTERM set a stop flag; the main loop exits cleanly, without a traceback.
- [ ] Check (root): `sudo python3 -m sniffer -i lo -c 5` together with `ping -c 3 127.0.0.1` in another terminal shows packets.

## Stage 2. pcap writing
- [x] `pcap_writer.py`: class `PcapWriter(path, snaplen, linktype=1)` — a context manager that writes the global header on open.
- [x] `write(ts_ns: int, data: bytes, orig_len: int | None = None)` — truncates to snaplen, keeps `orig_len`, calls `flush()` after each record.
- [x] `test_pcap_writer.py`: write 2 known packets to a temporary file and compare the bytes; if `dpkt` or `scapy` is installed, read the file back with it and compare (the test is skipped if the library is missing).
- [ ] Check (root): `sudo python3 -m sniffer -i eth0 -w out.pcap -c 20 -q && tcpdump -nr out.pcap | wc -l` gives 20.

## Stage 3. Header parsing
- [x] `PacketInfo` and nested dataclasses for Ethernet, IPv4, IPv6, TCP, UDP, ICMP; `truncated` and `malformed` flags.
- [x] Ethernet + one VLAN tag.
- [x] IPv4 with IHL and fragmentation.
- [x] IPv6 with extension header skipping.
- [x] TCP (flags, seq/ack), UDP; ICMP/ICMPv6 type and code only.
- [x] `tests/packets.py`: bytes of reference packets (TCP/IPv4 SYN, UDP/IPv6 DNS, VLAN, IPv4 with options, IPv6 with Hop-by-Hop, ICMP echo).
- [x] `test_parse.py`: fields match the reference; a packet truncated at every length from 0 to full does not raise; unknown EtherType.

## Stage 4. Real-time output
- [x] `output.py`: `format_line(pkt: RawPacket, info: PacketInfo) -> str` in the format from `AGENTS.md`.
- [x] `hexdump(data: bytes) -> str`: 16-byte lines with an offset and an ASCII column, like `tcpdump -X`.
- [x] `-x` enables the dump, `-q` disables packet output; line-buffered stdout.
- [x] Final statistics on exit (captured, passed the filter, written, skipped as non-Ethernet).
- [x] `test_output.py` on the reference packets.

## Stage 5. Filtering
- [x] `filter.py`: `parse_filter(expr: str) -> Filter` (a list of conditions joined by `and`), `Filter.match(info: PacketInfo) -> bool`.
- [x] A syntax error produces a clear message naming the bad token and exit code 2.
- [x] The filter is applied before output and before writing to pcap; `-c` counts only packets that passed.
- [x] `test_filter.py` on the reference packets: every condition and their combinations, IPv4 and IPv6 addresses.

## Stage 6. Robustness and performance
- [ ] Loopback: drop `PACKET_OUTGOING` duplicates; non-Ethernet interfaces are skipped when writing, with a warning (once per interface).
- [ ] Packets longer than snaplen are truncated correctly and `orig_len` is preserved.
- [ ] Hot loop without unnecessary copies (`recv_into`, `memoryview`, precompiled `struct.Struct`).
- [ ] Fuzz test: 100,000 random buffers of random length go through `parse` without unhandled exceptions (fixed seed).
- [ ] Benchmark: `ping -f` or `iperf3` on `lo` for 10 seconds; report the real packets per second.

## Stage 7. Integration test and documentation
- [ ] `tests/test_integration.py` (`@pytest.mark.root`, skipped without root): runs capture on `lo` with `-w` in a subprocess, generates traffic (UDP and TCP via `socket` on localhost), verifies with `tcpdump -r` (and `tshark -r` if available) and the packet count, checks the filter `-f "udp and port 9999"`.
- [ ] `README.md` in Russian: installation, privileges (`sudo`), all flags, examples, limitations.

## Optional extensions (only after stage 7)
- [ ] `or`, `not`, parentheses in the filter.
- [ ] LINKTYPE_LINUX_SLL for capturing on all interfaces, including non-Ethernet ones.
- [ ] File rotation by size (`-C MB`).
- [ ] Colored terminal output (behind a flag, no external libraries).
- [ ] Alternative backends: libpcap via `ctypes` or nfqueue (`--backend=pcap|nfqueue`).

## Decisions
The agent records deviations from `AGENTS.md` here, with the date and the reason.
