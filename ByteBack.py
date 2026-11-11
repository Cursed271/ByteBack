# ----- License -------------------------------------------------- # 

#  ByteBack - ByteBack decodes F5 BIG IP persistence cookies, 
#  extracts backend addressing metadata, and constructs IPv4 cookie values 
#  for authorized infrastructure assessments.
#  Copyright (c) 2026 - CursedSec (Operated by Cursed271). All rights reserved.

#  This software is an proprietary intellectual property developed for
#  penetration testing, threat modeling, and security research. It   
#  is licensed under the CURSEDSEC OWNERSHIP EDICT:
#
#  🚫 PROHIBITION WARNING 🚫
#  Redistribution, re-uploading, and unauthorized modification are strictly forbidden 
#  under the COE. Use is granted ONLY under the limited terms defined in the official 
#  LICENSE file (COE), which must be included in all copies.

#  DISCLAIMER:
#  This tool is intended for **educational or ethical testing** purposes only.
#  Unauthorized or malicious use of this software against systems without 
#  proper authorization is strictly prohibited and may violate laws and regulations.
#  The author assumes no liability for misuse or damage caused by this tool.

#  🔗 LICENSE: CURSEDSEC OWNERSHIP EDICT (COE)
#  🔗 Repository: https://github.com/Cursed271
#  🔗 Author: Steven Pereira (@Cursed271)

# ----- Libraries ------------------------------------------------ #

import os
import re
import sys
import typer
import struct
import urllib3
import requests
import ipaddress
from pathlib import Path
from rich.rule import Rule
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich.console import Console
import typer.rich_utils as typer_rich
from typing import Any, Dict, List, Optional, Tuple

# ----- Global Declaration --------------------------------------- #

console = Console()
app = typer.Typer(rich_markup_mode="rich")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ----- Cookie Crafter ------------------------------------------- #

def cookie_decoder(raw_cookie: str) -> Dict[str, Any]:
    cleaned = raw_cookie.strip().strip('"').strip("'")
    cookie_name = "Unknown Pool"
    if "=" in cleaned:
        cookie_name, val = cleaned.split("=", 1)
        cookie_name = cookie_name.strip()
        val = val.strip()
    else:
        val = cleaned
    pool_name = cookie_name
    if cookie_name.lower().startswith("bigipserver"):
        pool_name = cookie_name[11:]
    if val.startswith("rd"):
        parts = val.split("o")
        rd_id = parts[0][2:]
        ip_hex = parts[1]
        port = int(parts[2])
        if "ffff" in ip_hex and len(ip_hex) == 32:
            raw_ip = ip_hex[-8:]
            ip_obj = ipaddress.IPv4Address(int(raw_ip, 16))
            ip_type = "IPv4 (Route Domain)"
        else:
            ip_obj = ipaddress.IPv6Address(int(ip_hex, 16))
            ip_type = "IPv6 (Route Domain)"
        decoded_ip = str(ip_obj)
        route_domain = rd_id
    elif val.startswith("vi"):
        parts = val[2:].split(".")
        ip_hex = parts[0]
        port_raw = int(parts[1])
        port = struct.unpack(">H", struct.pack("<H", port_raw))[0]
        ip_obj = ipaddress.IPv6Address(int(ip_hex, 16))
        decoded_ip = str(ip_obj)
        ip_type = "IPv6"
        route_domain = "0 (Default)"
    else:
        parts = val.split(".")
        if len(parts) < 2:
            raise ValueError(f"Invalid F5 BIG-IP cookie format: {val}")
        host_int = int(parts[0])
        port_raw = int(parts[1])
        decoded_ip = ".".join(str(b) for b in struct.pack("<I", host_int))
        # Reverse little-endian port bytes
        port = struct.unpack(">H", struct.pack("<H", port_raw))[0]
        ip_type = "IPv4 (Standard)"
        route_domain = "0 (Default)"
    try:
        ip_check = ipaddress.ip_address(decoded_ip)
        is_internal = ip_check.is_private or ip_check.is_loopback or ip_check.is_reserved
        classification = "INTERNAL RFC-1918 (Sensitive Leak)" if is_internal else "PUBLIC / ROUTABLE"
    except Exception:
        classification = "UNKNOWN"
    return {
        "cookie_name": cookie_name,
        "pool_name": pool_name or "Default",
        "raw_value": val,
        "type": ip_type,
        "ip": decoded_ip,
        "port": port,
        "route_domain": route_domain,
        "classification": classification
    }

# ----- Cookie Decoder ------------------------------------------- #

def cookie_crafter(ip: str, port: int, pool_name: str = "custom_pool") -> str:
    octets = [int(x) for x in ip.split(".")]
    host_int = struct.unpack("<I", bytes(octets))[0]
    port_encoded = struct.unpack("<H", struct.pack(">H", port))[0]
    cookie_val = f"{host_int}.{port_encoded}.0000"
    return f"BIGipServer{pool_name}={cookie_val}"

# ----- Cookie Fetcher ------------------------------------------- #

def fetch_cookies_from_url(url: str) -> List[str]:
    session = requests.Session()
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )
    })
    cookies_found = []
    resp = session.get(url, timeout=8, verify=False, allow_redirects=True)
    for c_name, c_val in resp.cookies.items():
        if "bigip" in c_name.lower():
            cookies_found.append(f"{c_name}={c_val}")
    raw_headers = resp.headers.get("Set-Cookie", "")
    for match in re.finditer(r"(BIGipServer[^\s=;]+)=([^\s;]+)", raw_headers, re.IGNORECASE):
        cookie_str = f"{match.group(1)}={match.group(2)}"
        if cookie_str not in cookies_found:
            cookies_found.append(cookie_str)
    return cookies_found

# ----- Summary Table -------------------------------------------- #

def render_result_table(results: List[Dict[str, Any]]) -> None:
    tbl = Table(
        title="[bold white]ByteBack - F5 BIG-IP Infrastructure Telemetry[/bold white]",
        border_style="#C6ECE3",
        header_style="#C6ECE3",
        expand=False
    )
    tbl.add_column("Discovered Parameter", style="bold white", justify="left")
    tbl.add_column("Decoded Infrastructure Value", style="cyan", justify="left")
    tbl.add_column("Security Posture", style="yellow", justify="left")
    for res in results:
        tbl.add_row("Virtual Server Pool", res["pool_name"], f"F5 Type: {res['type']}")
        tbl.add_row("Backend Node IP", f"[bold white on #1F2937] {res['ip']} [/bold white on #1F2937]", res["classification"])
        tbl.add_row("Target Service Port", str(res["port"]), "TCP Service Member")
        tbl.add_row("Route Domain Partition", res["route_domain"], "VLAN / Network Segregation")
        tbl.add_row("Raw Cookie Name", res["cookie_name"], "Set-Cookie Header")
        tbl.add_section()
    console.print()
    console.print(tbl)
    console.print()

# ----- Orchestration -------------------------------------------- #

def orchestrate(target: str) -> None:
    target_clean = target.strip().strip('"').strip("'")
    results = []
    if target_clean.lower().startswith("http://") or target_clean.lower().startswith("https://"):
        console.print(f"[#2ECC71][+] ByteBack querying target endpoint: [bold white]{target_clean}[/bold white]")
        with console.status(f"[bold #FFB86C][!] Harvesting HTTP response headers for F5 BIG-IP cookies...", spinner="dots"):
            try:
                cookies = fetch_cookies_from_url(target_clean)
                if not cookies:
                    console.print(f"[bold #FF6B6B][!] No F5 BIG-IP persistence cookies found on this server.")
                    return
                for c in cookies:
                    results.append(cookie_decoder(c))
            except Exception as e:
                console.print(f"[bold #FF6B6B][!] Failed to connect to {target_clean}: {e}")
                return
    else:
        console.print(f"[#2ECC71][+] ByteBack parsing provided BIG-IP cookie string...")
        try:
            results.append(cookie_decoder(target_clean))
        except Exception as e:
            console.print(f"[bold #FF6B6B][!] Decoding error: {e}")
            return
    render_result_table(results)
    internal_leaked = any("INTERNAL" in r["classification"] for r in results)
    if internal_leaked:
        console.print(Panel(
            "[bold red]CRITICAL INFRASTRUCTURE LEAK DETECTED:[/bold red]\n"
            "The load balancer is exposing raw internal private IP addresses (RFC 1918) to the public web.\n\n"
            "[bold white]Remediation (F5 BIG-IP LTM Hardening):[/bold white]\n"
            "1. In the BIG-IP Configuration Utility, navigate to: [bold cyan]Local Traffic -> Profiles -> Persistence -> Cookie[/bold cyan]\n"
            "2. Select the Cookie Persistence Profile applied to the Virtual Server.\n"
            "3. Enable [bold green]'Cookie Encryption'[/bold green] and define a secure Passphrase.\n"
            "4. Alternatively, use an iRule to mask the internal node mapping before egress.",
            title="[bold red]Perimeter Defense Warning[/bold red]",
            border_style="red",
            width=banner_width
        ))

# ----- ASCII Banner --------------------------------------------- #

def ascii() -> int:
    art_content = rf"""
oooooooooo.                  .             oooooooooo.                      oooo
`888'   `Y8b               .o8             `888'   `Y8b                     `888
 888     888 oooo    ooo .o888oo  .ooooo.   888     888  .oooo.    .ooooo.   888  oooo
 888oooo888'  `88.  .8'    888   d88' `88b  888oooo888' `P  )88b  d88' `"Y8  888 .8P'
 888    `88b   `88..8'     888   888ooo888  888    `88b  .oP"888  888        888888.
 888    .88P    `888'      888 . 888    .o  888    .88P d8(  888  888   .o8  888 `88b.
o888bood8P'      .8'       "888" `Y8bod8P' o888bood8P'  `Y888""8o `Y8bod8P' o888o o888o
             .o..P'
             `Y8P'
"""
    art_color = Text(art_content, style = "#C6ECE3")
    art_panel = Panel(art_color, border_style = "#C6ECE3", expand = False)
    console.print(art_panel)
    banner_width = console.measure(art_panel).maximum
    console.print(Rule(style = "#C6ECE3 blink"), width = banner_width)
    console.print(f"  [~] Created by [bold red blink]Cursed271[/bold red blink]")
    console.print(f"  [~] ByteBack - Decode the cookie. Reveal the backend.")
    console.print(Rule(style = "#C6ECE3 blink"), width = banner_width)
    console.print()
    return banner_width

# ----- Argument Parser - Decode --------------------------------- #

@app.command()
def decode(
    target: Optional[str] = typer.Option(None, "--target", "-t", help="URL or raw BIG-IP cookie string"),
) -> None:
    if not target:
        target = Prompt.ask(f"[#C6ECE3][?]  Enter Target URL or BIG-IP Cookie string")
    orchestrate(target)

# ----- Argument Parser - Craft ---------------------------------- #

@app.command()
def craft(
    ip: str = typer.Option(..., "--ip", "-i", help="Target backend IP to encode"),
    port: int = typer.Option(..., "--port", "-p", help="Target backend port"),
    pool: str = typer.Option("app_pool", "--pool", help="Pool name suffix"),
) -> None:
    ascii_banner_needed = True
    cookie_str = cookie_crafter(ip, port, pool)
    console.print(f"[#2ECC71][+] Successfully crafted F5 BIG-IP Persistence Cookie:[/]")
    console.print(Panel(
        f"[bold white]Target Backend:[/bold white] {ip}:{port}"
        f"[bold white]Pool Name:[/bold white] BIGipServer{pool}"
        f"[bold cyan]Crafted Cookie:[/bold cyan] [bold green]{cookie_str}[/bold green]",
        title="[bold #C6ECE3]ByteBack Cookie Crafter[/bold #C6ECE3]",
        border_style="#C6ECE3",
        width=banner_width
    ))

# ----- Main Function -------------------------------------------- #

if __name__ == "__main__":
    os.system("cls" if os.name == "nt" else "clear")
    banner_width = ascii()
    typer_rich.MAX_WIDTH = banner_width
    app()

# ----- End ------------------------------------------------------ #