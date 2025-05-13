import socket
import argparse
import struct
import time
import os

# Konstanter
HEADER_FORMAT = '!HHHH'  # Sequence (16bit), Acknowledgment (16bit), Flags (16bit), Receiver Window (16bit)
HEADER_SIZE = 8
DATA_SIZE = 992
PACKET_SIZE = 1000
TIMEOUT = 0.4  # 400ms

# Flag konstanter
FLAG_SYN = 0b0100
FLAG_ACK = 0b0010
FLAG_FIN = 0b1000


def create_packet(seq, ack, flags, recv_window, data=b''):
    header = struct.pack(HEADER_FORMAT, seq, ack, flags, recv_window)
    return header + data


def parse_packet(packet):
    header = packet[:HEADER_SIZE]
    data = packet[HEADER_SIZE:]
    seq, ack, flags, recv_window = struct.unpack(HEADER_FORMAT, header)
    return seq, ack, flags, recv_window, data


def server(ip, port, discard_seq=None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
    print(f"Server listening on {ip}:{port}")

    # 3-way handshake
    data, addr = sock.recvfrom(1024)
    seq, ack, flags, recv_window, _ = parse_packet(data)
    if flags & FLAG_SYN:
        print("SYN packet is received")
        synack_packet = create_packet(0, seq+1, FLAG_SYN | FLAG_ACK, 15)
        sock.sendto(synack_packet, addr)
        print("SYN-ACK packet is sent")
        data, addr = sock.recvfrom(1024)
        seq, ack, flags, recv_window, _ = parse_packet(data)
        if flags & FLAG_ACK:
            print("ACK packet is received")
            print("Connection established")

    received_data = {}
    expected_seq = 1
    start_time = time.time()
    total_bytes = 0

    while True:
        try:
            packet, addr = sock.recvfrom(2048)
            seq, ack, flags, recv_window, data = parse_packet(packet)
            now = time.strftime('%H:%M:%S', time.localtime()) + f".{int(time.time()*1000000)%1000000:06d}"[-6:]

            if flags & FLAG_FIN:
                print("FIN packet is received")
                finack_packet = create_packet(0, seq+1, FLAG_FIN | FLAG_ACK, 0)
                sock.sendto(finack_packet, addr)
                print("FIN ACK packet is sent")
                break

            if seq == discard_seq:
                print(f"Discarding packet {seq}")
                discard_seq = 99999999  # discard bare én gang
                continue

            if seq == expected_seq:
                print(f"{now} -- packet {seq} is received")
                ack_packet = create_packet(0, seq, FLAG_ACK, 15)
                sock.sendto(ack_packet, addr)
                print(f"{now} -- sending ack for the received {seq}")
                received_data[seq] = data
                total_bytes += len(data)
                expected_seq += 1
            else:
                # Ignorer pakker som kommer feil
                continue

        except socket.timeout:
            continue

    end_time = time.time()
    throughput = (total_bytes * 8) / (end_time - start_time) / 1_000_000
    print(f"The throughput is {throughput:.2f} Mbps")
    print("Connection Closes")

    # Lagre filen
    with open("received_file", 'wb') as f:
        for i in range(1, expected_seq):
            f.write(received_data[i])


def client(ip, port, file_path, window_size):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    addr = (ip, port)

    # 3-way handshake
    syn_packet = create_packet(0, 0, FLAG_SYN, 0)
    sock.sendto(syn_packet, addr)
    print("SYN packet is sent")

    data, addr = sock.recvfrom(1024)
    seq, ack, flags, recv_window, _ = parse_packet(data)
    if flags & FLAG_SYN and flags & FLAG_ACK:
        print("SYN-ACK packet is received")
        ack_packet = create_packet(0, seq+1, FLAG_ACK, 0)
        sock.sendto(ack_packet, addr)
        print("ACK packet is sent")
        print("Connection established")

    window_size = min(window_size, recv_window)
    base = 1
    next_seq = 1
    packets = []

    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(DATA_SIZE)
            if not chunk:
                break
            packets.append(create_packet(next_seq, 0, 0, 0, chunk))
            next_seq += 1

    total_packets = len(packets)
    next_seq = 1

    # Send packets med Go-Back-N
    while base <= total_packets:
        while next_seq < base + window_size and next_seq <= total_packets:
            now = time.strftime('%H:%M:%S', time.localtime()) + f".{int(time.time()*1000000)%1000000:06d}"[-6:]
            sock.sendto(packets[next_seq-1], addr)
            print(f"{now} -- packet with seq = {next_seq} is sent, sliding window = {{{', '.join(map(str, range(base, next_seq+1)))}}}")
            next_seq += 1

        try:
            sock.settimeout(TIMEOUT)
            data, addr = sock.recvfrom(1024)
            seq, ack, flags, recv_window, _ = parse_packet(data)
            if flags & FLAG_ACK:
                print(f"ACK for packet = {ack} is received")
                base = ack + 1
        except socket.timeout:
            # Timeout, resend alle pakker i vinduet
            next_seq = base

    print("DATA Finished")

    # FIN avslutning
    fin_packet = create_packet(0, 0, FLAG_FIN, 0)
    sock.sendto(fin_packet, addr)
    print("FIN packet is sent")

    data, addr = sock.recvfrom(1024)
    seq, ack, flags, recv_window, _ = parse_packet(data)
    if flags & FLAG_FIN and flags & FLAG_ACK:
        print("FIN ACK packet is received")
    print("Connection Closes")


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-s', '--server', action='store_true')
    group.add_argument('-c', '--client', action='store_true')
    parser.add_argument('-i', '--ip', default='127.0.0.1')
    parser.add_argument('-p', '--port', type=int, default=8088)
    parser.add_argument('-f', '--file')
    parser.add_argument('-w', '--window', type=int, default=3)
    parser.add_argument('-d', '--discard', type=int, default=99999999)

    args = parser.parse_args()

    if args.server:
        server(args.ip, args.port, discard_seq=args.discard)
    else:
        if not args.file:
            print("Client mode requires a file path (-f)")
            return
        client(args.ip, args.port, args.file, args.window)


if __name__ == '__main__':
    main()