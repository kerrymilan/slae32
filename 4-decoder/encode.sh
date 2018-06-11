#!/bin/bash

[ -z $1 ] && echo "Usage: $(basename $(readlink -f $0)) <shellcode>"

for i in $(echo $1 | tr ',' ' '); do
    echo 0x${i:3}${i:2:1}
done | tr "\n" "," | rev | cut -c2- | rev
