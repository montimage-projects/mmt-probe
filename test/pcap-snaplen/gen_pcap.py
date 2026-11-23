#!/usr/bin/env python3
"""Write a classic libpcap file of fixed-size Ethernet/IPv4/UDP frames.

Helper of check_snaplen.sh; needs only the standard library. Each frame is
Ethernet II + IPv4 + UDP to the discard port (9) with valid checksums, and
the packets are spread over ``flows`` distinct 5-tuples so that the probe's
SMP hash dispatches them to more than one worker.

The snap length written in the file header is the frame size itself: the
tightest bound a well-formed capture can declare. ``snap_len`` overrides
it, e.g. to write a header declaring a huge snap length while the frames
stay small.

Usage: gen_pcap.py OUT FRAME_BYTES PACKETS [FLOWS] [SNAP_LEN]
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


def _frame(i: int, size: int, flows: int) -> bytes:
    src_ip = 0xC6120000 | (i % flows)  # 198.18.0.0/16, RFC 2544 benchmark range
    dst_ip = 0xC6130000 | (i % flows)  # 198.19.0.0/16
    sport = 49152 + (i % 16000)
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
    flows = int(sys.argv[4]) if len(sys.argv) > 4 else 64
    snap_len = int(sys.argv[5]) if len(sys.argv) > 5 else frame_size
    if frame_size < 50:
        raise ValueError("frame size must fit Ethernet+IPv4+UDP+seqno (50 B)")
    if snap_len < frame_size:
        raise ValueError("snap length must cover a whole frame")
    with open(out, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snap_len, 1))
        for i in range(packets):
            frame = _frame(i, frame_size, flows)
            usec = i * 10
            f.write(
                struct.pack(
                    "<IIII",
                    1_700_000_000 + usec // 1_000_000,
                    usec % 1_000_000,
                    len(frame),
                    len(frame),
                )
            )
            f.write(frame)


if __name__ == "__main__":
    main()
