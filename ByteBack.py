# ----- License -------------------------------------------------- # 

#  ByteBack - ByteBack is an open-source utility for ethical testing, traffic inspection, and controlled decoding of F5 BIG-IP cookies in authorized environments.
#  Copyright (c) 2025 - Steven Pereira aka Cursed.

#  This software is an open-source cybersecurity tool developed for
#  penetration testing, threat modeling, and security research. It   
#  is licensed under the MIT License, allowing free use, modification, 
#  and distribution under the following conditions:
#
#  You MUST include this copyright notice in all copies.
#  You MAY use this software for personal or educational purposes ONLY.
#  This software is provided "AS IS," WITHOUT WARRANTY of any kind. 
#  You MAY NOT use this software for any illegal or unauthorized activity.

#  DISCLAIMER:
#  This tool is intended for **educational or ethical testing** purposes only.
#  Unauthorized or malicious use of this software against systems without 
#  proper authorization is strictly prohibited and may violate laws and regulations.
#  The author assumes no liability for misuse or damage caused by this tool.

#  🔗 License: MIT License
#  🔗 Repository: https://github.com/Cursed271
#  🔗 Author: Steven Pereira (@Cursed271)

# ----- Libraries ------------------------------------------------ #

import os
import re
import struct
import subprocess
from rich.console import Console

# ----- Global Declaration --------------------------------------- #

console = Console()

# ----- Decode F5 Cookie ----------------------------------------- #

def cookie_decode(cookie):
	try:
		name, value = cookie.split("=", 1)
		host, port, *_ = value.split(".")
		ip_address = ".".join(str(b) for b in struct.pack("<I", int(host)))
		port_number = int.from_bytes(struct.pack("<H", int(port)), "big")
		console.print(rf"[#C6ECE3][+] Cookie: {name}={value}")
		console.print(rf"[#C6ECE3][+] Decoded Cookie: {ip_address}:{port_number}")
		console.print(rf"[#C6ECE3][+] ByteBack has successfully decoded the F5 Cookie.")
	except:
		console.print(rf"[bold red][!] ByteBack failed to decode the F5 Cookie.")

# ----- Fetch F5 Cookie ------------------------------------------ #

def cookie_extract(choice):
	if choice.lower().startswith("http"):
		try:
			output = subprocess.check_output(["curl", "-skI", choice], text=True)
			cookies = re.findall(r"Set-Cookie:\s*(BIGip[^=]+=[^;\s]+)", output, re.I)
			if not cookies:
				console.print(rf"[bold red][!] ByteBack couldn't find any F5 Cookies.")
			else:
				for c in cookies:
					cookie_decode(c)
		except:
			console.print(rf"[bold red][!] ByteBack failed to decode the F5 Cookie.")
	else:
		cookie_decode(choice)

# ----- Banner --------------------------------------------------- #

def ascii():
	console.print(rf"""[#C6ECE3]
┌───────────────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                               │
│    oooooooooo.                  .             oooooooooo.                      oooo           │ 
│    `888'   `Y8b               .o8             `888'   `Y8b                     `888           │ 
│     888     888 oooo    ooo .o888oo  .ooooo.   888     888  .oooo.    .ooooo.   888  oooo     │ 
│     888oooo888'  `88.  .8'    888   d88' `88b  888oooo888' `P  )88b  d88' `"Y8  888 .8P'      │ 
│     888    `88b   `88..8'     888   888ooo888  888    `88b  .oP"888  888        888888.       │ 
│     888    .88P    `888'      888 . 888    .o  888    .88P d8(  888  888   .o8  888 `88b.     │ 
│    o888bood8P'      .8'       "888" `Y8bod8P' o888bood8P'  `Y888""8o `Y8bod8P' o888o o888o    │
│                 .o..P'                                                                        │
│                 `Y8P'                                                                         │
│                                                                                               │
└───────────────────────────────────────────────────────────────────────────────────────────────┘
	""")
	console.print(rf"[#C6ECE3]+--------------------------------------------------------------+")
	console.print(rf"[#C6ECE3]  ByteBack - Crack the Code. Own the Macro.")
	console.print(rf"[#C6ECE3]  Created by [bold black]Cursed271")
	console.print(rf"[#C6ECE3]+--------------------------------------------------------------+")

# ----- Main Function -------------------------------------------- #

if __name__ == "__main__":
	os.system("cls" if os.name == "nt" else "clear")
	ascii()
	choice = console.input(f"[#C6ECE3][?] Enter the Target URL or the BIG-IP Cookie: ")
	cookie_extract(choice)
	console.print("[#C6ECE3]+--------------------------------------------------------------+")

# ----- End ------------------------------------------------------ #