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
        software-properties-common \
        sudo curl build-essential vim-tiny gdb git \
        python-dev python-setuptools python-pip libgraphviz-dev libc6-dev-i386 \
        bear libssl-dev zip

RUN apt-get update && \
    add-apt-repository -y ppa:deadsnakes/ppa && \
    apt-get update && \
    apt-get install -y python3.6 && \
    bash -c "curl https://bootstrap.pypa.io/get-pip.py | python3.6" 
    
RUN pip3.6 install setuptools --upgrade && \
    pip3.6 install pyyaml && \
    git clone https://github.com/agurfinkel/verifyTrusty.git && \
    chown -R usea.usea /opt/verifyTrusty 

WORKDIR /opt/verifyTrusty
USER usea
RUN echo "Installing Trusty" && \
    cd /opt/verifyTrusty && \
    mkdir /home/usea/bin/ && curl https://storage.googleapis.com/git-repo-downloads/repo > /home/usea/bin/repo && \
    chmod a+x /home/usea/bin/repo && \
    python3.6 /home/usea/bin/repo init -u https://android.googlesource.com/trusty/manifest -b master && \
    python3.6 /home/usea/bin/repo sync -j32 && \
    cp trusty/vendor/google/aosp/scripts/build.py build.py.oirg && \
    git remote update && git pull origin master && cp bear_build.py trusty/vendor/google/aosp/scripts/build.py && \
    trusty/vendor/google/aosp/scripts/build.py generic-arm32 && \
    python3.6 seahorn/gen_bc.py --jobs storage_ipc_indirect_handlers storage_ipc_msg_buffer storage_ipc_port_create_destroy
USER usea
