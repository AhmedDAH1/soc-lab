"""
Packet tap for the live console: report every TCP packet on the target's
interface, with the header fields NetScan's Suricata rule looks at (source
port, sequence number, window, header length).

This is only for showing the traffic. Detection is Suricata's job; this
script decides nothing. It reads packets with a raw socket (the sensor
already has NET_RAW) and needs nothing installed.

The sensor's own webhooks to SOAR-Lite leave through the same interface, so
packets to or from SOAR-Lite are left out.
"""

import os
import socket
import struct
import sys
import time
from urllib.parse import urlparse

from labevents import emit

INTERFACE = os.environ.get("LAB_TAP_INTERFACE", "eth0")
MAX_PACKETS = int(os.environ.get("LAB_TAP_MAX_PACKETS", "20000"))
ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
FLAG_NAMES = ((0x02, "S"), (0x10, "A"), (0x04, "R"), (0x01, "F"), (0x08, "P"), (0x20, "U"))
PAYLOAD_STARTS = (b"GET ", b"HEAD ", b"POST ", b"PUT ", b"OPTIONS ", b"HTTP/", b"SSH-")


def soar_addresses():
    """SOAR-Lite's addresses, so the sensor's own webhook traffic is not shown."""
    host = urlparse(os.environ.get("SOAR_URL", "http://soar:8000")).hostname or "soar"
    for _ in range(30):
        try:
            return {info[4][0] for info in socket.getaddrinfo(host, None, socket.AF_INET)}
        except OSError:
            time.sleep(1)
    return set()


def text_line(payload):
    """First line of a readable payload (an HTTP request or reply, an SSH banner), and its User-Agent."""
    if not payload.startswith(PAYLOAD_STARTS):
        return None, None
    lines = payload[:1024].split(b"\r\n")
    first = lines[0][:160].decode("latin-1")
    agent = next((line[11:].strip()[:200].decode("latin-1") for line in lines[1:]
                  if line[:11].lower() == b"user-agent:"), None)
    return first, agent


def parse(frame):
    """An Ethernet frame as a packet event's fields, or None if it isn't IPv4 TCP."""
    if len(frame) < 34 or struct.unpack("!H", frame[12:14])[0] != ETH_P_IP:
        return None
    ip_header_length = (frame[14] & 0x0F) * 4
    if frame[14] >> 4 != 4 or frame[23] != socket.IPPROTO_TCP:
        return None
    total_length = struct.unpack("!H", frame[16:18])[0]
    tcp = 14 + ip_header_length
    if len(frame) < tcp + 20:
        return None
    sport, dport, seq, _ack, offset_flags, window = struct.unpack("!HHIIHH", frame[tcp:tcp + 16])
    header_length = (offset_flags >> 12) * 4
    flags = "".join(name for bit, name in FLAG_NAMES if offset_flags & bit)
    payload = frame[tcp + header_length:14 + total_length]
    line, agent = text_line(payload)
    packet = {
        "src": socket.inet_ntoa(frame[26:30]), "sport": sport,
        "dst": socket.inet_ntoa(frame[30:34]), "dport": dport,
        "flags": flags, "seqno": seq, "win": window, "hdr": header_length, "len": len(payload),
    }
    if line:
        packet["line"] = line
    if agent:
        packet["agent"] = agent
    return packet


def main():
    try:
        tap = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
        tap.bind((INTERFACE, 0))
    except OSError as e:
        print(f"[tap] no packet view in the console: {e}", flush=True)
        emit("packets", "tap", "unavailable", reason=str(e))
        return 0
    ignore = soar_addresses()
    print(f"[tap] showing TCP packets on {INTERFACE} in the console (leaving out SOAR-Lite {sorted(ignore)})", flush=True)
    emit("packets", "tap", "ready", interface=INTERFACE)
    seen = 0
    while seen < MAX_PACKETS:
        packet = parse(tap.recv(65535))
        if not packet or packet["src"] in ignore or packet["dst"] in ignore:
            continue
        seen += 1
        emit("packets", "tap", "packet", **packet)
    emit("packets", "tap", "full", limit=MAX_PACKETS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
