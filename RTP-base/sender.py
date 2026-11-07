import argparse
import select
import socket
import sys
import time

from utils import (
    TYPE_START,
    TYPE_END,
    TYPE_DATA,
    TYPE_ACK,
    MAX_PAYLOAD_SIZE,
    build_packet,
    unpack_packet,
)

TIMEOUT = 0.5


def sender(receiver_ip, receiver_port, window_size):
    data = sys.stdin.buffer.read()

    if len(data) == 0:
        chunks = []
    else:
        chunks = [
            data[i : i + MAX_PAYLOAD_SIZE]
            for i in range(0, len(data), MAX_PAYLOAD_SIZE)
        ]
    total_packets = len(chunks)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    target = (receiver_ip, receiver_port)

    try:
        start_pkt = build_packet(TYPE_START, 0)
        sock.sendto(start_pkt, target)
        last_start_send = time.time()

        while True:
            r, _, _ = select.select([sock], [], [], 0.1)
            if r:
                try:
                    raw_data, _ = sock.recvfrom(2048)
                    hdr, _ = unpack_packet(raw_data)
                    if hdr and hdr.type == TYPE_ACK and hdr.seq_num in (0, 1):
                        break
                except (BlockingIOError, socket.error):
                    pass

            if time.time() - last_start_send >= 1.0:
                sock.sendto(start_pkt, target)
                last_start_send = time.time()

        base = 1
        next_seq_num = 1
        timer_start = None

        while base <= total_packets:
            while next_seq_num < base + window_size and next_seq_num <= total_packets:
                pkt = build_packet(TYPE_DATA, next_seq_num, chunks[next_seq_num - 1])
                sock.sendto(pkt, target)
                if timer_start is None:
                    timer_start = time.time()
                next_seq_num += 1

            if timer_start is not None:
                remaining = TIMEOUT - (time.time() - timer_start)
            else:
                remaining = TIMEOUT

            readable, _, _ = select.select([sock], [], [], max(0.0, remaining))

            if readable:
                while True:
                    try:
                        raw_data, _ = sock.recvfrom(2048)
                    except (BlockingIOError, socket.error):
                        break

                    hdr, _ = unpack_packet(raw_data)
                    if hdr and hdr.type == TYPE_ACK:
                        ack_seq = hdr.seq_num
                        if ack_seq > base:
                            base = ack_seq
                            if base < next_seq_num:
                                timer_start = time.time()
                            else:
                                timer_start = None

            if timer_start is not None and (time.time() - timer_start >= TIMEOUT):
                for seq in range(base, next_seq_num):
                    pkt = build_packet(TYPE_DATA, seq, chunks[seq - 1])
                    sock.sendto(pkt, target)
                timer_start = time.time()

        end_seq = total_packets + 1
        end_pkt = build_packet(TYPE_END, end_seq)
        sock.sendto(end_pkt, target)

        end_timer_start = time.time()
        while time.time() - end_timer_start < TIMEOUT:
            rem = TIMEOUT - (time.time() - end_timer_start)
            if rem <= 0:
                break
            readable, _, _ = select.select([sock], [], [], rem)
            if readable:
                try:
                    raw_data, _ = sock.recvfrom(2048)
                except (BlockingIOError, socket.error):
                    continue
                hdr, _ = unpack_packet(raw_data)
                if hdr and hdr.type == TYPE_ACK and hdr.seq_num == end_seq:
                    break

    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "receiver_ip", help="The IP address of the host that receiver is running on"
    )
    parser.add_argument(
        "receiver_port", type=int, help="The port number on which receiver is listening"
    )
    parser.add_argument(
        "window_size", type=int, help="Maximum number of outstanding packets"
    )
    args = parser.parse_args()

    sender(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
