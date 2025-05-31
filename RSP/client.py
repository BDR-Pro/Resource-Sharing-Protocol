# pylint: disable=line-too-long , import-error
"""Test client for RSP server using TLS."""
# demo_client.py
import socket
from module import create_certificate, create_tls_client_context, encode_packet, decode_packet, pretty_print_packet, PacketMeta

# Create TLS client context
create_certificate("client.crt", "client.key", "ca.crt")
context = create_tls_client_context("client.crt", "client.key", "ca.crt")

# Connect to server
raw_sock = socket.create_connection(("localhost", 9090))
tls_sock = context.wrap_socket(raw_sock, server_hostname="rsp-server")
print("🔐 Connected to RSP server")

# Send REQUEST_VM
meta = PacketMeta(cmd_id=1, flags=2)  # Encrypted
payload = {
    "cpu": 2,
    "ram": 4,
    "duration": 60,
    "provider": "qemu"
}
packet = encode_packet(meta, payload)
tls_sock.sendall(packet)
print("📤 Sent REQUEST_VM")

# Receive response
response = tls_sock.recv(4096)
packet = decode_packet(response)
pretty_print_packet(packet)
