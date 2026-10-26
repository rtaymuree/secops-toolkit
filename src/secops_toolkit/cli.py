import argparse
from pathlib import Path

from secops_toolkit import checks


def print_report(info: dict, ports: dict, risky: dict) -> None:
    print(f"Host:   {info['hostname']}")
    print(f"OS:     {info['os']}")
    print(f"CPU:    {info['cpu_percent']}%   RAM: {info['memory_percent']}%   Disk: {info['disk_percent']}%")
    print("\nListening ports:")
    for port, name in ports.items():
        flag = f"  <-- RISKY: {risky[port]}" if port in risky else ""
        print(f"  {port:<6} {name}{flag}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="secops-toolkit", description="Beginner IT admin and security toolkit"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("report", help="Show system info and listening ports")
    sub.add_parser("prompt", help="Build an AI prompt from the report")
    args = parser.parse_args()

    info = checks.system_info()
    ports = checks.listening_ports()
    risky = checks.risky_ports(ports)

    if args.command == "report":
        print_report(info, ports, risky)
    else:
        text = checks.build_ai_prompt(info, ports, risky)
        print(text)
        Path("ai_prompt.txt").write_text(text, encoding="utf-8")
        print("Saved to ai_prompt.txt")
        