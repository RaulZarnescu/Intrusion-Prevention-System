#!/bin/bash
set -e

JENKINS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$JENKINS_DIR/.env"
ENV_EXAMPLE="$JENKINS_DIR/.env.example"

echo "== Intrusion-Prevention-System: Jenkins bootstrap =="

if ! command -v docker >/dev/null 2>&1; then
    echo "Docker not found. Installing via the official Docker convenience script..."
    curl -fsSL https://get.docker.com | sudo sh
else
    echo "Docker already installed, skipping install."
fi

if ! docker compose version >/dev/null 2>&1; then
    echo "ERROR: 'docker compose' (the plugin) is not available even after install." >&2
    echo "Install it manually for your distro, then re-run this script." >&2
    exit 1
fi

if ! groups "$USER" | grep -q '\bdocker\b'; then
    echo "Adding $USER to the docker group (needed to run docker without sudo)..."
    sudo usermod -aG docker "$USER"
    echo
    echo "You were just added to the 'docker' group. This only takes effect in a"
    echo "new shell session. Log out and back in (or run 'newgrp docker'), then"
    echo "re-run ./setup.sh to continue."
    exit 0
fi

if [ ! -f "$ENV_FILE" ]; then
    echo
    echo "No .env found — let's create one (jenkins-setup/.env)."
    cp "$ENV_EXAMPLE" "$ENV_FILE"

    read -rp "Jenkins admin username [admin]: " admin_id
    admin_id="${admin_id:-admin}"

    read -rsp "Jenkins admin password: " admin_password
    echo
    while [ -z "$admin_password" ]; do
        read -rsp "Password can't be empty, try again: " admin_password
        echo
    done

    read -rsp "GitHub personal access token (repo scope): " github_token
    echo

    read -rsp "Ngrok auth token: " ngrok_token
    echo

    sed -i \
        -e "s|^JENKINS_ADMIN_ID=.*|JENKINS_ADMIN_ID=${admin_id}|" \
        -e "s|^JENKINS_ADMIN_PASSWORD=.*|JENKINS_ADMIN_PASSWORD=${admin_password}|" \
        -e "s|^GITHUB_TOKEN=.*|GITHUB_TOKEN=${github_token}|" \
        -e "s|^NGROK_AUTHTOKEN=.*|NGROK_AUTHTOKEN=${ngrok_token}|" \
        "$ENV_FILE"

    echo ".env written to $ENV_FILE"
else
    echo ".env already present, skipping prompts."
fi

echo
echo "Building and starting the stack..."
(cd "$JENKINS_DIR" && docker compose up -d --build)

echo
echo -n "Waiting for Jenkins to come up"
for _ in $(seq 1 60); do
    if curl -fsS -o /dev/null "http://localhost:8081/login" 2>/dev/null; then
        echo
        echo "Jenkins is up: http://localhost:8081"
        echo "(also reachable at whatever domain the ngrok container is configured for)"
        exit 0
    fi
    echo -n "."
    sleep 2
done

echo
echo "Jenkins didn't come up within the timeout. Check logs with:"
echo "  (cd jenkins-setup && docker compose logs -f jenkins)"
exit 1
