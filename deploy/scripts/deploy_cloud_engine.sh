#!/usr/bin/env bash
# Deploy Bartholomew Cloud Control Plane & Data Centre Remote Attestation to Google Cloud Run
set -euo pipefail

PROJECT_ID="${GCP_PROJECT_ID:-bartholomew-prod}"
REGION="${GCP_REGION:-us-central1}"
SERVICE_NAME="bartholomew-cloud-engine"
IMAGE_TAG="gcr.io/${PROJECT_ID}/${SERVICE_NAME}:6.4.3"

echo "================================================================="
echo " Deploying Bartholomew Cloud Control Plane to Google Cloud Run"
echo " Project : ${PROJECT_ID}"
echo " Region  : ${REGION}"
echo " Image   : ${IMAGE_TAG}"
echo "================================================================="

gcloud builds submit \
  --project="${PROJECT_ID}" \
  --tag="${IMAGE_TAG}" \
  --file=deploy/docker/Dockerfile.cloud-engine .

gcloud run deploy "${SERVICE_NAME}" \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --image="${IMAGE_TAG}" \
  --platform=managed \
  --allow-unauthenticated \
  --memory=1Gi \
  --cpu=2 \
  --min-instances=1 \
  --max-instances=10 \
  --port=8080 \
  --set-env-vars="BTP_ENV=production,BTP_VERSION=6.4.3"

echo "[SUCCESS] Bartholomew Cloud Control Plane deployed successfully!"
