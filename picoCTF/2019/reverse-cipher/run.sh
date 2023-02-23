#! /bin/sh -e

make

echo

mv rev_this flag.txt

xxd -p rev patch.hex
sed -e 's/83c005/83e805/g;s/83e802/83c002/g' -i patch.hex
xxd -r -p patch.hex patch
chmod u+x patch

./patch
cat rev_this


