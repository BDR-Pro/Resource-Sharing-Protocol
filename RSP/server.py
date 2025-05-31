# pylint: disable=import-error
"""Server for RSP Protocol using TLS"""
# server.py
import socket
import ssl
from module import create_tls_server_context, decode_packet
from module import encode_packet, PacketMeta, create_certificate,pretty_print_packet



# Create TLS server context
create_certificate("server.crt", "server.key", "sr.crt")
context = create_tls_server_context("server.crt", "server.key", "sr.crt")

# Bind and listen on secure socket
bindsock = socket.socket()
bindsock.bind(("0.0.0.0", 9090))
bindsock.listen(1)
print("🔒 RSP Server listening on port 9090")

conn, addr = bindsock.accept()
try:
    with context.wrap_socket(conn, server_side=True) as tls_conn:
        print(f"🔗 Connection accepted from {addr}")

        # Receive data
        data = tls_conn.recv(4096)
        packet = decode_packet(data)
        print("📨 Received:")
        pretty_print_packet(packet)

        # Respond with VM_OFFER if CMD is REQUEST_VM
        if packet["cmd_id"] == 1:
            response_meta = PacketMeta(cmd_id=2, flags=0)
            response_payload = {
                "vm_id": "qemu-001",
                "price": 0.002,
                "boot_time": "15s"
            }
            response_data = encode_packet(response_meta, response_payload)
            tls_conn.sendall(response_data)
            print("✅ VM_OFFER sent.")
except ssl.SSLError as e:
    print(f"SSL error: {e}")
    conn.close()
