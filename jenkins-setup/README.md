# Jenkins CI/CD Setup

Infrastructure-as-Code for the Jenkins instance that builds and tests the Intrusion
Prevention System. The whole instance — security realm, credentials, and the pipeline
job — is defined declaratively via Jenkins Configuration as Code (JCasC) and Job DSL
(`casc/jenkins.yaml`). Nothing is carried between machines as opaque state; the only
thing that moves is this repo plus a handful of secrets.

## Moving this to a new machine

Run the bootstrap script from inside this folder:

```bash
cd jenkins-setup
./setup.sh
```

It will:
1. Install Docker (via the official convenience script) if it isn't already present.
2. Add you to the `docker` group if needed (you'll be asked to re-login and re-run).
3. Create `jenkins-setup/.env` and prompt you once for the four secrets it needs
   (Jenkins admin username/password, a GitHub token, and an ngrok auth token) — skipped
   automatically if `.env` already exists.
4. `docker compose up -d --build`.
5. Wait for Jenkins to come up and print the URL.

That's the whole setup. Re-running `./setup.sh` on a machine that's already configured
just re-syncs the containers — it won't re-prompt or reinstall anything.

Note: step 3 creates `.env` in this folder (`jenkins-setup/.env`), right next to
`.env.example` — same place `docker compose` expects to find it.

## What happens under the hood?

- `Dockerfile` builds on `jenkins/jenkins:lts`, installing the C/eBPF toolchain
  (`clang`, `cmake`, `bpftool`, etc.) and all plugins from `plugins.txt`.
- `casc/jenkins.yaml` is baked into the image and applied automatically on every boot
  (via `CASC_JENKINS_CONFIG`): it creates the admin user from `JENKINS_ADMIN_ID` /
  `JENKINS_ADMIN_PASSWORD`, a GitHub credential from `GITHUB_TOKEN`, and the
  `ips-pipeline` job (via Job DSL) pointed at this repo's `Jenkinsfile` with a GitHub
  push trigger. There is no manual "New Item" step, ever.
- `entrypoint.sh` maps the host's `docker.sock` GID into the container so the Flood
  Test stage can spawn sibling containers, then starts Jenkins.
- A sidecar `ngrok` container forwards the static domain `clear-stowing-rebirth.ngrok-free.dev`
  to Jenkins, for the GitHub webhook.

## Secrets

`jenkins-setup/.env` is gitignored — it holds real credentials and is never committed.
`.env.example` documents the required keys. If you lose `.env`, there's nothing to
recover: just re-run `./setup.sh`, re-enter the secrets, and JCasC rebuilds the exact
same instance from scratch.
