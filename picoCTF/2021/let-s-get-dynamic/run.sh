#! /bin/sh -e

make

echo

echo "Running binary..."
LD_PRELOAD=./debug.so ./a.out


