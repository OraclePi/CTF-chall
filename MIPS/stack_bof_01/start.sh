#! /bin/bash
cp $(which qemu-mipsel-static) ./q
./q  -L ./ -g 1234 ./stack_bof_01 "`cat payload`"

