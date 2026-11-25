#!/usr/bin/env python3
"""Write a classic libpcap file of fixed-size Ethernet/IPv4/UDP frames
that all belong to a single 5-tuple.

Helper of check_uninit_timer.sh; needs only the standard library. Each
frame is Ethernet II + IPv4 + UDP to the discard port (9) with valid
checksums, and every frame repeats the same addresses and ports, so the
probe's SMP hash dispatches the whole capture to a single worker ring.
The remaining workers keep spinning on their empty rings for the whole
capture - the case under test.

Usage: gen_oneflow_pcap.py OUT FRAME_BYTES PACKETS
"""

import struct
import sys


def _sum16(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    return sum(struct.unpack(f">{len(data) // 2}H", data))


def _fold(total: int) -> int:
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def _frame(i: int, size: int) -> bytes:
    src_ip = 0xC6120001  # 198.18.0.1, RFC 2544 benchmark range
    dst_ip = 0xC6130001  # 198.19.0.1
    sport = 49152
    ip_len = size - 14
    udp_len = ip_len - 20
    payload = struct.pack(">Q", i) + bytes(udp_len - 8 - 8)
    ip = struct.pack(
        ">BBHHHBBHII", 0x45, 0, ip_len, 0, 0x4000, 64, 17, 0, src_ip, dst_ip
    )
    ip = ip[:10] + struct.pack(">H", 0xFFFF - _fold(_sum16(ip))) + ip[12:]
    udp = struct.pack(">HHH", sport, 9, udp_len)
    pseudo = struct.pack(">IIBBH", src_ip, dst_ip, 0, 17, udp_len)
    cksum = 0xFFFF - _fold(_sum16(pseudo) + _sum16(udp) + _sum16(payload))
    eth = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00"
    return eth + ip + udp + struct.pack(">H", cksum or 0xFFFF) + payload


def main() -> None:
    out, frame_size, packets = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    if frame_size < 50:
        raise ValueError("frame size must fit Ethernet+IPv4+UDP+seqno (50 B)")
    with open(out, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, frame_size, 1))
        for i in range(packets):
            #increasing, microsecond-resolution timestamps
            f.write(
                struct.pack(
                    "<IIII",
                    1700000000 + i // 1000,
                    (i % 1000) * 1000,
                    frame_size,
                    frame_size,
                )
                + _frame(i, frame_size)
            )


if __name__ == "__main__":
    main()
