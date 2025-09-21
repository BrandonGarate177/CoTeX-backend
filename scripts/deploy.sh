#!/bin/bash

# Deploy script for CoTeX backend
set -e

echo "🚀 Deploying CoTeX backend to Google Cloud Run..."

# Build and deploy using Cloud Build
gcloud builds submit --config cloudbuild.yaml .

