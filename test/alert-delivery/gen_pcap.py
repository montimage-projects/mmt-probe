#!/usr/bin/env python3
"""Write a classic libpcap file whose last packets raise security alerts.

Helper of check_alert_delivery.sh; needs only the standard library. The
capture holds ``benign`` Ethernet/IPv4/UDP frames, then ``alerts`` TCP SYN
segments that carry a payload, one per flow, as the very last packets of
the capture. mmt-security's rule 13 ("Data in SYN packet") raises exactly
one alert on each of them, so the expected number of alerts is known and
they are all raised at the end of the capture, just before the probe
stops. The flows use distinct address pairs so that the probe's SMP hash
spreads them over its workers. Packets are 1 ms apart: far from the SYN
rate of rule 57, and no SYN-ACK is sent, so rule 56 has nothing to count.

Usage: gen_pcap.py OUT [ALERTS] [BENIGN]
"""

import struct
import sys

T0 = 1700000000  # packet time of the first packet, in seconds


def _sum16(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    return sum(struct.unpack(f">{len(data) // 2}H", data))


def _fold(total: int) -> int:
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def _ipv4(proto: int, src: int, dst: int, payload: bytes) -> bytes:
    ip = struct.pack(
        ">BBHHHBBHII", 0x45, 0, 20 + len(payload), 0, 0x4000, 64, proto, 0, src, dst
    )
    ip = ip[:10] + struct.pack(">H", 0xFFFF - _fold(_sum16(ip))) + ip[12:]
    return ip + payload


def _l4_checksum(proto: int, src: int, dst: int, segment: bytes) -> int:
    pseudo = struct.pack(">IIBBH", src, dst, 0, proto, len(segment))
    return 0xFFFF - _fold(_sum16(pseudo) + _sum16(segment))


ETH = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00"


def _udp_frame(i: int) -> bytes:
    src = 0xC6120000 | (i % 64)  # 198.18.0.0/16, RFC 2544 benchmark range
    dst = 0xC6130000 | (i % 64)  # 198.19.0.0/16
    payload = struct.pack(">Q", i) + bytes(24)
    udp = struct.pack(">HHHH", 49152 + i % 16000, 9, 8 + len(payload), 0) + payload
    ck = _l4_checksum(17, src, dst, udp) or 0xFFFF
    udp = udp[:6] + struct.pack(">H", ck) + udp[8:]
    return ETH + _ipv4(17, src, dst, udp)


def _syn_with_data_frame(i: int) -> bytes:
    src = 0xC6120100 | i  # 198.18.1.x: one client per flow
    dst = 0xC6130100 | i  # 198.19.1.x
    payload = b"data-in-syn-%04d" % i
    tcp = struct.pack(">HHIIBBHHH", 40000 + i, 80, 1000 + i, 0, 5 << 4, 0x02, 64240, 0, 0)
    ck = _l4_checksum(6, src, dst, tcp + payload)
    tcp = tcp[:16] + struct.pack(">H", ck) + tcp[18:]
    return ETH + _ipv4(6, src, dst, tcp + payload)


def main() -> None:
    out = sys.argv[1]
    alerts = int(sys.argv[2]) if len(sys.argv) > 2 else 12
    benign = int(sys.argv[3]) if len(sys.argv) > 3 else 200
    if not 1 <= alerts <= 255:
        raise ValueError("ALERTS must be from 1 to 255")
    frames = [_udp_frame(i) for i in range(benign)]
    frames += [_syn_with_data_frame(i) for i in range(1, alerts + 1)]
    with open(out, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for n, frame in enumerate(frames):
            ts_us = n * 1000
            f.write(
                struct.pack(
                    "<IIII", T0 + ts_us // 1000000, ts_us % 1000000, len(frame), len(frame)
                )
            )
            f.write(frame)


if __name__ == "__main__":
    main()
