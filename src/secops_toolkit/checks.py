import os
import platform
import shutil
import socket

import psutil

RISKY_PORTS = {
    21: "FTP (unencrypted file transfer)",
    23: "Telnet (unencrypted remote login)",
    135: "RPC (Windows remote procedure calls)",
    139: "NetBIOS (legacy file sharing)",
    445: "SMB (Windows file sharing)",
    3389: "RDP (Remote Desktop)",
    5900: "VNC (remote screen control)",
}


def system_info() -> dict:
    disk = shutil.disk_usage(os.path.abspath(os.sep))
    mem = psutil.virtual_memory()
    return {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "cpu_percent": psutil.cpu_percent(interval=1),
        "memory_percent": mem.percent,
        "disk_percent": round(disk.used / disk.total * 100, 1),
    }


def is_exposed(address: str) -> bool:
    return address not in ("127.0.0.1", "::1")


def listening_ports() -> dict:
    found = {}
    for conn in psutil.net_connections(kind="inet"):
        if conn.status == psutil.CONN_LISTEN:
            try:
                name = psutil.Process(conn.pid).name() if conn.pid else "unknown"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                name = "unknown"
            port = conn.laddr.port
            exposed = is_exposed(conn.laddr.ip)
            entry = found.get(port)
            if entry is None or (exposed and not entry["exposed"]):
                found[port] = {"process": name, "address": conn.laddr.ip, "exposed": exposed}
    return dict(sorted(found.items()))


def risky_ports(ports: dict) -> dict:
    return {p: RISKY_PORTS[p] for p in ports if p in RISKY_PORTS}


def build_ai_prompt(info: dict, ports: dict, risky: dict) -> str:
    port_lines = "\n".join(
        f"- {p}: {v['process']} ({'reachable from network' if v['exposed'] else 'localhost only'})"
        for p, v in ports.items()
    )
    risky_lines = "\n".join(f"- {p}: {desc}" for p, desc in risky.items()) or "- none flagged"
    return f"""You are a friendly senior IT security mentor. I am a beginner IT administrator.
Review this snapshot of my own Windows machine and:
1. Explain in plain English what each listening port is likely used for.
2. Tell me which ones could be a security risk and why.
3. Give me safe, step-by-step hardening actions, easiest first.
4. Tell me what to check next.

System:
- OS: {info['os']}
- CPU usage: {info['cpu_percent']}%
- Memory usage: {info['memory_percent']}%
- Disk usage: {info['disk_percent']}%

Listening ports (port: process):
{port_lines}

Ports my tool flagged as risky:
{risky_lines}
"""


WINDOWS_CORE = {
    "svchost.exe", "system", "lsass.exe",
    "wininit.exe", "services.exe", "spoolsv.exe",
}


def redact_ports(ports: dict) -> dict:
    redacted = {}
    for port, d in ports.items():
        name = d["process"]
        if name.lower() not in WINDOWS_CORE:
            name = "third-party-app"
        redacted[port] = {**d, "process": name}
    return redacted