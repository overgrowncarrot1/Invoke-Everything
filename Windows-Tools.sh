#!/bin/bash

mkdir Tools
cd Tools
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
wget https://raw.githubusercontent.com/lucky-luk3/ActiveDirectory/master/PowerView-Dev.ps1
wget https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_linux_amd64.gz
gunzip chisel_1.8.1_linux_amd64.gz
wget https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_windows_amd64.gz
gunzip chisel_1.8.1_windows_amd64.gz
mv chisel_1.8.1_windows_amd64 chisel.exe
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_proxy_0.4.3_Linux_64bit.tar.gz
gunzip ligolo-ng_proxy_0.4.3_Linux_64bit.tar.gz
tar -xvf ligolo-ng_proxy_0.4.3_Linux_64bit
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_agent_0.4.3_Windows_64bit.zip
unzip ligolo-ng_agent_0.4.3_Windows_64bit.zip
wget https://github.com/int0x33/nc.exe/raw/master/nc64.exe
wget https://github.com/carlospolop/PEASS-ng/releases/download/20230702-bc7ce3ac/winPEASany.exe
wget https://github.com/antonioCoco/JuicyPotatoNG/releases/download/v1.1/JuicyPotatoNG.zip
unzip JuicyPotatoNG.zip
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe

