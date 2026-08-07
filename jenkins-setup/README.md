# Jenkins CI/CD Setup

This folder contains the Infrastructure-as-Code to run the Jenkins environment for the Intrusion Prevention System. 
It automates the installation of the C/eBPF build toolchain, handles Docker-in-Docker socket permissions, and sets up Ngrok for GitHub Webhooks.

## How to move this to a new machine

1. Copy your `jenkins_state.tar.gz` from the original machine into this directory (`jenkins-setup/`). 
   *(Note: This file is gitignored because it contains secrets like your Jenkins admin hash. You must move it manually via USB/SCP, etc. or remove it from `.gitignore` at your own risk if you want to push it to a private repo).*
2. Copy `.env.example` to `.env` and fill in your Ngrok auth token:
   ```bash
   cp .env.example .env
   ```
3. Run the setup:
   ```bash
   docker compose up -d --build
   ```

## What happens under the hood?

- The `Dockerfile` builds a custom image based on `jenkins/jenkins:lts`. It installs all required apt packages (`clang`, `cmake`, `bpftool`, `docker.io`, etc.) and pre-installs all Jenkins plugins via `plugins.txt`.
- On boot, the `entrypoint.sh` script detects the `docker.sock` GID on the host machine and automatically adds the Jenkins user to that group so the `Flood Test` stage can spawn sibling Docker containers without permission errors.
- It also unpacks `jenkins_state.tar.gz` into the container on its very first run, instantly restoring all your jobs, users, and build history.
- A sidecar `ngrok` container spins up, connects to Jenkins, and forwards it to your static domain `clear-stowing-rebirth.ngrok-free.dev`.
