#!/usr/bin/env python3
"""
mc_ping.py - Query a Minecraft (Java Edition) server using the Server List Ping protocol.

Pulls: MOTD, icon, online players, max players (plus version, sample players, latency).
No third-party dependencies required.

Usage:
    python mc_ping.py mc.hypixel.net
    python mc_ping.py example.com:25566
    python mc_ping.py example.com --icon myicon.png
    python mc_ping.py example.com --json
"""

import argparse
import base64
import json
import re
import socket
import struct
import sys
import time


# ---------- Low-level protocol helpers ----------

def pack_varint(value: int) -> bytes:
    value &= 0xFFFFFFFF
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def pack_string(s: str) -> bytes:
    data = s.encode("utf-8")
    return pack_varint(len(data)) + data


def pack_packet(packet_id: int, payload: bytes = b"") -> bytes:
    body = pack_varint(packet_id) + payload
    return pack_varint(len(body)) + body


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed by server")
        buf.extend(chunk)
    return bytes(buf)


def read_varint_sock(sock: socket.socket) -> int:
    result = 0
    for i in range(5):
        byte = recv_exact(sock, 1)[0]
        result |= (byte & 0x7F) << (7 * i)
        if not byte & 0x80:
            return result
    raise ValueError("VarInt is too big")


def read_varint_buf(buf: bytes, pos: int):
    result = 0
    for i in range(5):
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << (7 * i)
        if not byte & 0x80:
            return result, pos
    raise ValueError("VarInt is too big")


def read_packet(sock: socket.socket) -> bytes:
    length = read_varint_sock(sock)
    return recv_exact(sock, length)


# ---------- MOTD handling ----------

def flatten_chat(component) -> str:
    """Convert a Minecraft chat component (str / dict / list) into plain text."""
    if isinstance(component, str):
        return component
    if isinstance(component, list):
        return "".join(flatten_chat(c) for c in component)
    if isinstance(component, dict):
        text = component.get("text", "")
        if not text and "translate" in component:
            text = component["translate"]
        return text + "".join(flatten_chat(c) for c in component.get("extra", []))
    return ""


def strip_formatting(text: str) -> str:
    """Remove legacy section-sign colour/format codes (e.g. §a, §l)."""
    return re.sub(r"§.", "", text)


# ---------- Optional SRV lookup ----------

def resolve_srv(host: str):
    """Try _minecraft._tcp SRV lookup (needs `dnspython`; silently skipped if missing)."""
    try:
        import dns.resolver  # type: ignore
        answers = dns.resolver.resolve(f"_minecraft._tcp.{host}", "SRV")
        rec = sorted(answers, key=lambda r: (r.priority, -r.weight))[0]
        return str(rec.target).rstrip("."), int(rec.port)
    except Exception:
        return None


# ---------- Main ping logic ----------

def ping_server(host: str, port: int = 25565, timeout: float = 5.0, protocol: int = -1) -> dict:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)

        # Handshake (next state = 1 -> status)
        handshake = (
            pack_varint(protocol)
            + pack_string(host)
            + struct.pack(">H", port)
            + pack_varint(1)
        )
        sock.sendall(pack_packet(0x00, handshake))

        # Status request
        sock.sendall(pack_packet(0x00))

        # Status response
        data = read_packet(sock)
        pos = 0
        packet_id, pos = read_varint_buf(data, pos)
        if packet_id != 0x00:
            raise ValueError(f"Unexpected packet id: {packet_id}")
        str_len, pos = read_varint_buf(data, pos)
        raw = data[pos:pos + str_len].decode("utf-8", errors="replace")
        status = json.loads(raw)

        # Latency (optional - some servers don't reply)
        latency_ms = None
        try:
            sent = time.perf_counter()
            sock.sendall(pack_packet(0x01, struct.pack(">q", int(time.time() * 1000))))
            read_packet(sock)
            latency_ms = round((time.perf_counter() - sent) * 1000, 1)
        except Exception:
            pass

    players = status.get("players", {})
    version = status.get("version", {})
    motd_raw = flatten_chat(status.get("description", ""))

    return {
        "host": host,
        "port": port,
        "motd": strip_formatting(motd_raw),
        "motd_raw": motd_raw,
        "online": players.get("online"),
        "max": players.get("max"),
        "sample": [p.get("name") for p in players.get("sample", []) if isinstance(p, dict)],
        "version_name": version.get("name"),
        "protocol": version.get("protocol"),
        "latency_ms": latency_ms,
        "favicon": status.get("favicon"),  # "data:image/png;base64,...."
    }


def save_icon(favicon: str, path: str) -> bool:
    if not favicon or "," not in favicon:
        return False
    with open(path, "wb") as f:
        f.write(base64.b64decode(favicon.split(",", 1)[1]))
    return True


def parse_address(addr: str):
    if addr.count(":") == 1:
        host, port = addr.split(":")
        return host, int(port), True
    return addr, 25565, False


def main():
    ap = argparse.ArgumentParser(description="Ping a Minecraft Java server.")
    ap.add_argument("address", help="host or host:port")
    ap.add_argument("--timeout", type=float, default=5.0, help="socket timeout in seconds")
    ap.add_argument("--icon", metavar="FILE", help="where to save the server icon (default: <host>_icon.png)")
    ap.add_argument("--no-icon", action="store_true", help="don't save the icon")
    ap.add_argument("--json", action="store_true", help="print result as JSON")
    args = ap.parse_args()

    host, port, explicit_port = parse_address(args.address)

    # Follow SRV record if no explicit port was given
    if not explicit_port:
        srv = resolve_srv(host)
        if srv:
            host, port = srv

    try:
        result = ping_server(host, port, timeout=args.timeout)
    except (socket.timeout, TimeoutError):
        sys.exit(f"Timed out connecting to {host}:{port}")
    except (ConnectionError, OSError) as e:
        sys.exit(f"Could not connect to {host}:{port} - {e}")
    except Exception as e:
        sys.exit(f"Failed to read status from {host}:{port} - {e}")

    # Save icon
    icon_path = None
    if not args.no_icon and result["favicon"]:
        icon_path = args.icon or f"{host.replace(':', '_')}_icon.png"
        save_icon(result["favicon"], icon_path)

    if args.json:
        out = dict(result)
        out["icon_saved_to"] = icon_path
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return

    print(f"Server:   {result['host']}:{result['port']}")
    print(f"MOTD:     {result['motd'].strip()}")
    print(f"Players:  {result['online']} / {result['max']}")
    if result["sample"]:
        print(f"Sample:   {', '.join(result['sample'])}")
    print(f"Version:  {result['version_name']} (protocol {result['protocol']})")
    if result["latency_ms"] is not None:
        print(f"Latency:  {result['latency_ms']} ms")
    print(f"Icon:     {icon_path if icon_path else 'none'}")


if __name__ == "__main__":
    main()