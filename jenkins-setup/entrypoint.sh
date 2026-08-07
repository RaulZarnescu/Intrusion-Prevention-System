#!/bin/bash
set -e

# Initialize Jenkins home if it's empty
if [ ! -d "/var/jenkins_home/jobs/ips-pipeline" ]; then
    echo "Initializing Jenkins home from state backup..."
    if [ -f "/var/jenkins_home_init/jenkins_state.tar.gz" ]; then
        tar -xzf /var/jenkins_home_init/jenkins_state.tar.gz -C /var/jenkins_home
        echo "State unpacked successfully."
    else
        echo "No jenkins_state.tar.gz found in /var/jenkins_home_init, proceeding with empty Jenkins."
    fi
fi

# Ensure ownership is correct
chown -R jenkins:jenkins /var/jenkins_home

# Dynamically map the host's docker socket GID to the jenkins user
DOCKER_SOCKET=/var/run/docker.sock
if [ -S "$DOCKER_SOCKET" ]; then
    DOCKER_GID=$(stat -c '%g' $DOCKER_SOCKET)
    echo "Mapping docker socket with GID $DOCKER_GID..."
    # Check if a group with this GID already exists
    if getent group $DOCKER_GID >/dev/null; then
        DOCKER_GROUP=$(getent group $DOCKER_GID | cut -d: -f1)
        usermod -aG "$DOCKER_GROUP" jenkins
    else
        groupadd -g $DOCKER_GID dockerhost
        usermod -aG dockerhost jenkins
    fi
else
    echo "Warning: /var/run/docker.sock not found. Docker-in-Docker stages will fail."
fi

# Start original jenkins entrypoint as the jenkins user
exec su jenkins -c "/usr/bin/tini -- /usr/local/bin/jenkins.sh"
