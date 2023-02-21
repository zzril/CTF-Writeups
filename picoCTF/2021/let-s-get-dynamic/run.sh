#! /bin/sh -e

make && echo && LD_PRELOAD=./debug.so ./a.out


