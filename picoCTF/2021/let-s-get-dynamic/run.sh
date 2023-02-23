#! /bin/sh -e

make

echo

echo "Running binary... (input expected)"
LD_PRELOAD=./debug.so ./a.out


