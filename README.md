# Verifying TEE applications with SeaHorn
Wiki and useful background materials: https://github.com/agurfinkel/verifyTrusty/wiki

## Background
Trusted Execution Environment(TEE) provides physically separate hardware for storing and processing sensitive data
With TEEs, even a compromised OS cannot access and leak sensitive data
Applications running on TEEs are juicy attack targets. The goal of this project is to apply formal verification techniques on applications running on TEEs with the state-of-the-art framework [SeaHorn](https://github.com/seahorn/seahorn).

## Setup
All harnesses and stubs within this repository depend on the *Trusty* repository. To run verification jobs locally, follow steps below to install/build missing dependencies and trusty:

#### Dependencies
- `clang-5.0` and `llvm-link-5.0`
- [Repo](https://source.android.com/setup/build/downloading#installing-repo)
- [Bear](https://github.com/rizsotto/Bear)
- SeaHorn, use [docker image](http://seahorn.github.io/seahorn/install/docker/2018/02/24/seahorn-with-docker.html) or [build from source](http://seahorn.github.io/seahorn/install/2016/10/14/install-seahorn.html) then set `$SEA` or `$SEAHORN` environment variable to `<path_to_build_dir>/run/bin/sea` executable.

#### Install and build trusty

1. Clone this repository

2. [download and install trusty](https://source.android.com/security/trusty/download-and-build) under the same directory.

3. [Build trusty](https://github.com/agurfinkel/verifyTrusty/wiki#building-trusty) and generate compile dependency list file with BEAR

Once the above steps are finished, you should see a file `compile_commands.json` in the current directory.

Alternatively, use our docker image to play around existing verification examples.


## Generating LLVM assembly for verification
SeaHorn can work with most LLVM based languages, including C, C++ and LLVM assembly. In order to model irrelevant or overly-complicated functions and data structures, stub files and harness file (code under verification that is slightly modified) are compiled individually into LLVM by `clang`, then linked together into the final target file by `llvm-link`.  After a trusty build is finished with compile dependencies stored in `compile_commands.json`, you can create LLVM assembly files for all jobs under `seahorn/jobs/` by running:

`python3 seahorn/gen_bc.py`

To see details of compilation and linking, add `--verbose` or `-v`

To do a "dry run" with no compilation or linking actually taking place, add `--dry`, prints the same details as `--verbose` mode

To run specific jobs `--jobs <dir_name>`

If LLVM bitcode generation is successful, you should see `out.bc` files under `seahorn/jobs/<job_name>/`.

### Current examples (under `seahorn/jobs/`)
1. `storage_ipc_port_create_destroy` simple example that shows `SeaHorn` can
   model simple ipc functions in the `storage` app like `ipc_port_create` and
   `ipc_port_destroy`; this example also shows that stubbing of handles table
   (`seahorn/lib/handle_table.c`) works.

    - Build command: `python3 seahorn/gen_bc.py --jobs storage_ipc_port_create_destroy`
    - Verification command: `$SEAHORN bpf -m32 -O3 --bmc=mono --horn-bv2=true  --horn-bv2-ptr-size=4 --horn-bv2-word-size=4 --no-lower-gv-init seahorn/jobs/storage_ipc_port_create_destroy/out.bc  --inline -S --devirt-functions=types`
    - Expected output: `unsat`, meaning no `sassert` is not violated.

2. `storage_ipc_indirect_handlers` the `storage` application use function
   pointers extensively for port/channel event handlers. This example
   demonstrates that `SeaHorn` can model this programming pattern by applying
   its function devirtualization pass.

    - Build command: `python3 seahorn/gen_bc.py --jobs storage_ipc_indirect_handlers`
    - Verification command: `$SEAHORN bpf -m32 -O3 --bmc=mono --horn-bv2=true  --horn-bv2-ptr-size=4 --horn-bv2-word-size=4 --no-lower-gv-init seahorn/jobs/storage_ipc_indirect_handlers/out.bc  --inline --devirt-functions  -S`
    - Expected output: `unsat`, meaning no `sassert` is not violated.

3. `storage_ipc_msg_buffer` test potential buffer overflow on `msg_buf` by stubbing `realloc`.

    - Build command: `python3 seahorn/gen_bc.py --jobs storage_ipc_msg_buffer`
    - Verification command: `$SEAHORN bpf -m32 -O3 --bmc=mono --horn-bv2=true  --horn-bv2-ptr-size=4 --horn-bv2-word-size=4 --no-lower-gv-init seahorn/jobs/storage_ipc_msg_buffer/out.bc  --inline --devirt-functions=sea-dsa  -S --externalize-addr-taken-functions`
    - Expected output: `unsat`, meaning no overflow is not possible. 
    - Try removing `return ERR_NOT_ENOUGH_BUFFER` block on line `150` in
      `ipc.c`, and rebuild the verification example. Doing so should
      result in `sat` because now overflow is possible.


