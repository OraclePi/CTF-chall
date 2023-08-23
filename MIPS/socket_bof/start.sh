#! /bin/bash
cp $(which qemu-mipsel-static) ./q
./q  -L ./ -g 1234  ./socket_bof "9999"

