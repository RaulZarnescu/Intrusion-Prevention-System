#!/bin/bash
set -e

JENKINS_VOL="/var/lib/docker/volumes/jenkins_home/_data"
DEST_TAR="jenkins_state.tar.gz"

echo "Exporting Jenkins state from $JENKINS_VOL..."

# We exclude directories that are huge and can be recreated:
# - plugins: We use plugins.txt and install them at build time
# - caches/updates/war: Automatically regenerated
# - workspace: Source code that will be re-cloned by the job
sudo tar -czf "$DEST_TAR" \
    --exclude="plugins" \
    --exclude="caches" \
    --exclude="updates" \
    --exclude="war" \
    --exclude="workspace" \
    --exclude="logs" \
    -C "$JENKINS_VOL" .

sudo chown $USER:$USER "$DEST_TAR"

echo "Successfully exported Jenkins state to $DEST_TAR"
echo "NOTE: This archive contains secrets and user hashes. Do NOT push it to a public GitHub repository."
