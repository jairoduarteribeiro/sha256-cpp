FROM jairoduarteribeiro/llvm-cmake-ninja:0.0.3

RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        vim \
        gnupg \
        openssh-client \
        bash-completion && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

USER dev
