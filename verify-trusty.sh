#!/bin/bash

: ${1?"Usage: $0 <bitcode_file> <sea_dir>  Need to pass bitcode file from trusty"}
: ${2:?"Usage: $0 <bitcode_file> <sea_dir> Need to pass SEA_DIR - i.e. the dir which contains the sea{,horn,opt} cmds e.g. seahorn/build/run/bin/"}

INPUT_FILE=${1}
shift
SEA_DIR=${1}
shift

OUT_DIR="$(dirname ${INPUT_FILE})"
FNAME="$(basename ${INPUT_FILE} | cut -d. -f1)"
FAT_LL=$OUT_DIR/$FNAME.fat.ll

${SEA_DIR}/seapp --horn-bnd-chk-slots=false -fat-bnd-check -S -o ${FAT_LL} ${INPUT_FILE}

${SEA_DIR}/sea bpf --sea-dsa=cs+t  -m32 -O0  --inline  --horn-bmc-engine=mono --horn-bmc --horn-bv2=true \
                   --log=opsem  --sea-opsem-allocator=normal  --keep-shadows=true --horn-bv2-simplify=true \
                   --horn-bv2-lambdas --horn-gsa --horn-vcgen-use-ite --horn-bv2-ptr-size=4 --horn-bv2-word-size=4 \
                   --horn-bv2-extra-widemem --keep-temps --temp-dir=/tmp/verify-trusty \
                   --lower-gv-init --lower-gv-init-struct=false  -S  --devirt-functions \
                   --oll=/tmp/trusty_fat_opt.ll --externalize-addr-taken-functions --keep-shadows \
                   ${FAT_LL} --sea-dsa-type-aware \
                   -o=/tmp/output.smt2 \
                   --horn-explicit-sp0=false $@
