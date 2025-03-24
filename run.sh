#!/bin/bash

gcc src/server.c -o server -l sqlite3
if [ $? -ne 0 ]; then
    echo "Eroare la compilarea server.c"
    exit -1
fi

gcc src/client.c -o client -l sqlite3
if [ $? -ne 0 ]; then
    echo "Eroare la compilarea client.c"
    exit -1
fi

clear

echo "S-a compilat cu succes"

./server
