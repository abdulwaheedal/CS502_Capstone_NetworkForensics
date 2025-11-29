import socket
import struct
import textwrap
import os

suspect_ips = {}

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ipv4(addr):
    return '.'.join(map(str, addr))

def main():
    if os.name == 'nt':
        print("WARNING: Raw sockets on Windows require strictly Admin privileges and IP binding.")
        host = input("Enter your local IP to bind: ")
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind((host, 0))
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    else:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    print("[*] Forensic Sniffer Started... Press Ctrl+C to stop.")
    
    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)
            
            if os.name != 'nt':
                dest_mac, src_mac, eth_proto, data = struct.unpack('! 6s 6s H', raw_data[:14])
                data = raw_data[14:]
            else:
                data = raw_data

            if len(data) >= 20:
                version_header_length = data[0]
                header_length = (version_header_length & 15) * 4
                ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
                src_ip = ipv4(src)
                
                if proto == 6:
                    t_header = data[header_length:header_length+20]
                    src_port, dest_port, seq, ack, offset_flags = struct.unpack('! H H L L H', t_header)
                    
                    flag_syn = (offset_flags & 2) >> 1
                    flag_ack = (offset_flags & 16) >> 4

                    if flag_syn == 1 and flag_ack == 0:
                        suspect_ips[src_ip] = suspect_ips.get(src_ip, 0) + 1
                        if suspect_ips[src_ip] > 10:
                            print(f"[ALERT] Potential SYN Flood Source Detected: {src_ip} | Count: {suspect_ips[src_ip]}")
                    
                    print(f"TCP Packet: {src_ip}:{src_port} -> {ipv4(target)}:{dest_port} | Flags: S:{flag_syn} A:{flag_ack}")

    except KeyboardInterrupt:
        print("\n[*] Sniffer Stopped.")

if __name__ == "__main__":
    main()
