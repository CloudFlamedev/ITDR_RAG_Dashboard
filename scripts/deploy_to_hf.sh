#!/usr/bin/env bash
# Deploy ITDR Backend to Hugging Face Spaces via Git Subtree
set -e

if [ -z "$1" ]; then
  echo "=========================================================="
  echo "  Deploy ITDR Backend to Hugging Face Spaces (Docker)     "
  echo "=========================================================="
  echo "Usage: ./scripts/deploy_to_hf.sh <YOUR_HF_USERNAME> [SPACE_NAME]"
  echo "Example: ./scripts/deploy_to_hf.sh CloudFlamedev itdr-backend-api"
  exit 1
fi

HF_USER="$1"
SPACE_NAME="${2:-itdr-backend-api}"
HF_REMOTE_URL="https://huggingface.co/spaces/${HF_USER}/${SPACE_NAME}"

echo "[1/3] Setting Hugging Face Space remote ($HF_REMOTE_URL)..."
if git remote | grep -q "^hf$"; then
  git remote set-url hf "$HF_REMOTE_URL"
else
  git remote add hf "$HF_REMOTE_URL"
fi

echo "[2/3] Extracting backend/ folder and pushing to Hugging Face Space..."
git subtree push --prefix backend hf main

echo "[3/3] Done!"
echo "Your backend container is building at: https://huggingface.co/spaces/${HF_USER}/${SPACE_NAME}"
echo "Once live, your public API URL is: https://${HF_USER}-${SPACE_NAME}.hf.space"
echo "Interactive Swagger Docs: https://${HF_USER}-${SPACE_NAME}.hf.space/docs"
