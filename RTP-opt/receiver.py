import argparse
import socket
import sys

from utils import (
    TYPE_START,
    TYPE_END,
    TYPE_DATA,
    TYPE_ACK,
    build_packet,
    unpack_packet,
)


def receiver(receiver_ip, receiver_port, window_size):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((receiver_ip, receiver_port))

    in_connection = False
    sender_addr = None
    expected_seq = 1
    packet_buffer = {}

    try:
        while True:
            raw_data, addr = sock.recvfrom(2048)
            hdr, payload = unpack_packet(raw_data)

            if hdr is None:
                continue

            if not in_connection:
                if hdr.type == TYPE_START:
                    in_connection = True
                    sender_addr = addr
                    expected_seq = 1
                    packet_buffer.clear()
                    ack = build_packet(TYPE_ACK, 1)
                    sock.sendto(ack, sender_addr)
                continue

            if hdr.type == TYPE_START:
                continue

            sender_addr = addr

            if hdr.type == TYPE_DATA:
                if hdr.seq_num >= expected_seq + window_size:
                    continue

                ack = build_packet(TYPE_ACK, hdr.seq_num)
                sock.sendto(ack, sender_addr)

                if hdr.seq_num < expected_seq:
                    continue

                if hdr.seq_num not in packet_buffer:
                    packet_buffer[hdr.seq_num] = payload

                while expected_seq in packet_buffer:
                    data_chunk = packet_buffer.pop(expected_seq)
                    sys.stdout.buffer.write(data_chunk)
                    expected_seq += 1
                sys.stdout.buffer.flush()

            elif hdr.type == TYPE_END:
                ack = build_packet(TYPE_ACK, hdr.seq_num)
                sock.sendto(ack, sender_addr)
                sys.stdout.buffer.flush()
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

    receiver(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
