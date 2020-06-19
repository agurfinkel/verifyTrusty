#
# Minimal Dockerfile for SeaHorn and verifyTrusty environment
# produces a lightweight container with SeaHorn, trusty source code and compiled harness files
#

FROM seahorn/seahorn-llvm10:nightly

ENV SEAHORN=/home/usea/seahorn/bin/sea PATH="$PATH:/home/usea/seahorn/bin:/home/usea/bin"

## install required pacakges
USER root
RUN echo "Pulling Verify Trusty environment" && \
    # installing repo
    mkdir ~/bin && PATH=~/bin:$PATH && \
    apt-get update && \
    apt-get install --no-install-recommends -yqq \
        software-properties-common \
        sudo curl build-essential vim gdb git \
        python-dev python-setuptools python-pip libgraphviz-dev libc6-dev-i386 \
        bear libssl-dev zip

## install pyyaml parser
RUN pip3 install setuptools --upgrade && \
    pip3 install pyyaml 

## clone verify-trusty repository
USER usea
WORKDIR /home/usea
RUN git clone https://github.com/agurfinkel/verifyTrusty.git 

## clony trusty repository (takes a long time)
WORKDIR /home/usea/verifyTrusty
RUN echo "Installing Trusty" && \
    cd /home/usea//verifyTrusty && \
    mkdir /home/usea/bin/ && curl https://storage.googleapis.com/git-repo-downloads/repo > /home/usea/bin/repo && \
    chmod a+x /home/usea/bin/repo && \
    python3 /home/usea/bin/repo init -u https://android.googlesource.com/trusty/manifest -b master && \
    python3 /home/usea/bin/repo sync -j32 

## use our custom build script
## TODO: use a patch instead of a copy of the script
RUN cp trusty/vendor/google/aosp/scripts/build.py build.py.oirg && \
    git remote update && git pull origin master && cp bear_build.py trusty/vendor/google/aosp/scripts/build.py 

## Build trusty. We use 32 bits because verification is easier with fewer bits.
## Maybe consider using 64-bits in the future
RUN trusty/vendor/google/aosp/scripts/build.py generic-arm32 

## To test that everything is working pre-generate bc files for our verification tasks
RUN python3 seahorn/gen_bc.py --jobs storage_ipc_indirect_handlers storage_ipc_msg_buffer storage_ipc_port_create_destroy

## set default user and wait for someone to login and start running verification tasks
USER usea
