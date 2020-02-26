#
# Minimal Dockerfile for SeaHorn and verifyTrusty environment
# produces a lightweight container with SeaHorn, trusty source code and compiled harness files
#

FROM seahorn/seahorn-llvm5:nightly

ENV SEAHORN=/opt/seahorn/bin/sea PATH="$PATH:/opt/seahorn/bin:/opt/llvm/bin:/home/usea/bin"
USER root

WORKDIR /opt

RUN echo "Pulling Verify Trusty environment" && \
    # installing repo
    mkdir ~/bin && PATH=~/bin:$PATH && \
    apt-get update && \
    apt-get install --no-install-recommends -yqq \
        sudo curl build-essential vim-tiny gdb git \
        python-dev python-setuptools python-pip libgraphviz-dev libc6-dev-i386 \
        python3 python3-pip bear libssl-dev zip && \
    python3 -m pip install setuptools --upgrade && \
    python3 -m pip install pyyaml && \
    git clone https://github.com/agurfinkel/verifyTrusty.git && \
    chown -R usea.usea /opt/verifyTrusty 

WORKDIR /opt/verifyTrusty
USER usea
RUN echo "Installing Trusty" && \
    cd /opt/verifyTrusty && \
    mkdir /home/usea/bin/ && curl https://storage.googleapis.com/git-repo-downloads/repo > /home/usea/bin/repo && \
    chmod a+x /home/usea/bin/repo && \
    /home/usea/bin/repo init -u https://android.googlesource.com/trusty/manifest -b master && \
    /home/usea/bin/repo sync -j32 && \
    git remote update && git pull origin master && cp bear_build.py trusty/vendor/google/aosp/scripts/build.py && \
    trusty/vendor/google/aosp/scripts/build.py generic-arm32 && \
    python3 seahorn/gen_bc.py --jobs storage_ipc_indirect_handlers storage_ipc_msg_buffer storage_ipc_port_create_destroy
USER usea
