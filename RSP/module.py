"""TLS connection handler and RSP protocol packet encoder/decoder module."""
import subprocess
from dataclasses import dataclass
import os
import shutil
from pathlib import Path
import ssl
import struct
import msgpack

DEFAULT_CERT_DIR = Path.home() / ".rsp_certs"
DEFAULT_CERT = DEFAULT_CERT_DIR / "me.crt"
DEFAULT_KEY = DEFAULT_CERT_DIR / "me.key"
DEFAULT_CA = DEFAULT_CERT_DIR / "peers" / "trusted.crt"

@dataclass
class PacketMeta:
    """Define metadata for RSP protocol packets."""
    cmd_id: int
    flags: int
    version: int = 1
    vpn_flag: int = 1
    trace_id: bytes = b'\x00\x00\x00\x00'

# Constants
HEADER_FMT = ">BBBBH4s"
HEADER_SIZE = struct.calcsize(HEADER_FMT)
"""
    HEADER_FMT = ">BBBBH4s"
    This string defines a format for the struct module to pack and unpack binary data.
    It's a compact specification for how a packet's header is laid out in bytes:

    > Big-endian byte order (most significant byte first).

    B  Unsigned char (1 byte). This appears four times, so:

    First B: version

    Second B: vpn_flag

    Third B: cmd_id

    Fourth B: flags

    H  Unsigned short (2 bytes), representing body_len (payload length).

    4s  4-byte string, representing trace_id.
"""

CMD_ID_MAP = {
    1: "REQUEST_VM",
    2: "VM_OFFER",
    3: "ACCEPT_OFFER",
    4: "VM_READY",
    5: "ESCROW_RESULT",
    255: "ERROR"
}

FLAGS_MAP = {
    1: "ACK",
    2: "Encrypted",
    4: "High Priority",
    8: "Compressed"
}


def ensure_openssl_config() -> str:
    """ find and create OpenSSL config file if it doesn't exist."""
    openssl_path = shutil.which("openssl")
    if not openssl_path:
        raise FileNotFoundError("OpenSSL binary not found in PATH")
    openssl_dir = Path(openssl_path).parent
    cfg_path = openssl_dir / "openssl.cnf"

    if not cfg_path.exists():
        print(f"⚠️ No OpenSSL config found, creating one at {cfg_path}")
        cfg_path.write_text("""[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
CN = localhost
""")

    os.environ["OPENSSL_CONF"] = str(cfg_path)
    return str(cfg_path)

def create_certificate(certfile: str, keyfile: str, cafile: str) -> None:
    """Create a self-signed certificate for testing purposes."""
    ensure_openssl_config()
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", keyfile, "-out", certfile,
        "-days", "365", "-nodes", "-subj", "/CN=localhost"
    ], check=True)
    subprocess.run(["openssl", "x509", "-in", certfile, "-text", "-noout"], check=True)
    shutil.copyfile(certfile, cafile)


def create_tls_server_context(
    certfile: str = str(DEFAULT_CERT),
    keyfile: str = str(DEFAULT_KEY),
    cafile: str = str(DEFAULT_CA)
) -> ssl.SSLContext:
    """Create a TLS server context using default or given cert/key/CA."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    context.load_verify_locations(cafile)
    # TODO: In production, enforce certificate verification
    context.check_hostname = False  # Accept self-signed for testing
    context.verify_mode = ssl.CERT_NONE  # <- WARNING: insecure, used for testing only
    return context


def create_tls_client_context(
    certfile: str = str(DEFAULT_CERT),
    keyfile: str = str(DEFAULT_KEY),
    cafile: str = str(DEFAULT_CA)
) -> ssl.SSLContext:
    """Create a TLS client context using default or given cert/key/CA."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    context.load_verify_locations(cafile)
    # TODO: In production, require trusted CA verification
    context.check_hostname = False  # Accept self-signed for testing
    context.verify_mode = ssl.CERT_NONE  # <- WARNING: insecure, used for testing only
    return context


#### Start of RSP Protocol Packet Encoding/Decoding ####

def encode_packet(meta: PacketMeta, payload: dict) -> bytes:
    """Encode a dictionary payload into an RSP protocol packet."""
    body = msgpack.packb(payload)
    header = struct.pack(HEADER_FMT, meta.version, meta.vpn_flag,
                         meta.cmd_id, meta.flags, len(body), meta.trace_id)
    return header + body


def decode_packet(data: bytes) -> dict:
    """Decode an RSP protocol packet into its components."""
    if len(data) < HEADER_SIZE:
        raise ValueError("Incomplete RSP packet")

    header_fields = list(struct.unpack(HEADER_FMT, data[:HEADER_SIZE]))
    version, vpn_flag, cmd_id, flags, body_len, trace_id = header_fields

    body = data[HEADER_SIZE:HEADER_SIZE + body_len]
    payload = msgpack.unpackb(body)

    return {
        "version": version,
        "vpn_flag": vpn_flag,
        "cmd_id": cmd_id,
        "flags": flags,
        "body_len": body_len,
        "trace_id": trace_id.hex(),
        "cmd_name": CMD_ID_MAP.get(cmd_id, "UNKNOWN"),
        "flags_str": [name for bit, name in FLAGS_MAP.items() if flags & bit],
        "payload": payload
    }


def pretty_print_packet(packet: dict) -> None:
    """Print a human-readable representation of an RSP packet."""
    print("\n🔍 RSP Packet:")
    print(f"  Version     : {packet['version']}")
    print(f"  VPN Flag    : {packet['vpn_flag']} ({'VPN' if packet['vpn_flag'] else 'Direct'})")
    print(f"  CMD_ID      : {packet['cmd_id']} ({packet['cmd_name']})")
    print(f"  FLAGS       : {packet['flags']} ({', '.join(packet['flags_str']) or 'None'})")
    print(f"  BODY_LEN    : {packet['body_len']} bytes")
    print(f"  TRACE_ID    : {packet['trace_id']}")
    print("  Payload     :")
    for k, v in packet["payload"].items():
        print(f"    {k}: {v}")
