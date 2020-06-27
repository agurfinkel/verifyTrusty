#!/bin/bash

: ${1?"Usage: $0 <bitcode_file> <sea_dir>  Need to pass bitcode file from trusty"}
: ${2:?"Usage: $0 <bitcode_file> <sea_dir> Need to pass SEA_DIR - i.e. the dir which contains the sea{,horn,opt} cmds e.g. seahorn/build/run/bin/"}

OUT_DIR="$(dirname ${1})"
FNAME="$(basename ${1}|cut -d. -f1)"
SEA_DIR=${2}
FAT_LL=$OUT_DIR/$FNAME.fat.ll

${SEA_DIR}/seapp --horn-bnd-chk-slots=false -fat-bnd-check -S -o ${FAT_LL} $1

${SEA_DIR}/sea bpf -sea-dsa=cs  -m32 -O3  --inline  --horn-bmc-engine=mono --horn-bmc --horn-bv2=true --log=opsem  --sea-opsem-allocator=static  --keep-shadows=true --horn-bv2-simplify=true --horn-bv2-lambdas --horn-gsa --horn-vcgen-use-ite ${FAT_LL}   --horn-bv2-ptr-size=4 --horn-bv2-word-size=4 --horn-bv2-extra-widemem --keep-temps --temp-dir=/tmp/verify-trusty --no-lower-gv-init -S --log=cex --devirt-functions --log=opsem --externalize-addr-taken-functions --keep-shadows 
