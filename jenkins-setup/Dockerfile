FROM jenkins/jenkins:lts

# Switch to root to install system dependencies and set up the entrypoint
USER root

# Install C/eBPF build toolchain and Docker CLI
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    zlib1g-dev \
    libbpf-dev \
    bpftool \
    cmake \
    pkg-config \
    docker.io \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Allow jenkins user to run sudo without password (useful for the flood test if needed)
RUN echo "jenkins ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Copy plugins.txt and pre-install all plugins
COPY plugins.txt /usr/share/jenkins/ref/plugins.txt
RUN jenkins-plugin-cli --plugin-file /usr/share/jenkins/ref/plugins.txt

# Configuration as Code: this is the whole instance (security, credentials, the
# pipeline job) defined declaratively. Jenkins applies it automatically on every
# boot because CASC_JENKINS_CONFIG is set, so there is no state to carry between
# machines beyond this file and the secrets in .env.
COPY casc/jenkins.yaml /usr/share/jenkins/ref/casc_configs/jenkins.yaml
ENV CASC_JENKINS_CONFIG=/usr/share/jenkins/ref/casc_configs

# Copy our custom entrypoint script
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# We must keep running as root so the entrypoint can do the socket permission mapping.
# The entrypoint will drop privileges to the `jenkins` user when starting the app.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
