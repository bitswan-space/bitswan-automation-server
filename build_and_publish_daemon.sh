#!/bin/bash

# Get Year and Commit Hash
YEAR=$(date +%Y)
COMMIT_HASH=$(git rev-parse --short HEAD)
IMAGE_TAG="bitswan/automation-server-daemon-runtime"
VERSIONED_TAG="$IMAGE_TAG:$YEAR-${GITHUB_RUN_ID}-git-$COMMIT_HASH"

# Build and push multi-arch Docker images (linux/amd64 + linux/arm64).
# buildx with --push handles the manifest list automatically.
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --push \
  -t "$IMAGE_TAG:latest" \
  -t "$VERSIONED_TAG" \
  .

# Also tag with the image digest for pinning.
IMAGE_ID=$(docker buildx imagetools inspect "$IMAGE_TAG:latest" --format '{{.Manifest.Digest}}' | sed 's/:/_/g')
docker buildx imagetools create \
  --tag "$IMAGE_TAG:$IMAGE_ID" \
  "$IMAGE_TAG:latest"
