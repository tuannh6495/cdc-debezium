#!/bin/bash

set -e

# Configuration
NAMESPACE="cdc-system"
ENVIRONMENT=${1:-dev}
RELEASE_NAME="cdc-system"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Deploying CDC System to ${ENVIRONMENT} environment${NC}"

# Create namespace if not exists
kubectl create namespace ${NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -

# Add required Helm repositories
echo -e "${YELLOW}Adding Helm repositories...${NC}"
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

# Deploy the CDC system
echo -e "${YELLOW}Deploying CDC system...${NC}"
helm upgrade --install ${RELEASE_NAME} ./helm-charts/cdc-system \
  --namespace ${NAMESPACE} \
  --values ./helm-charts/cdc-system/values.yaml \
  --values ./helm-charts/cdc-system/values-${ENVIRONMENT}.yaml \
  --wait \
  --timeout 15m

# Wait for all pods to be ready
echo -e "${YELLOW}Waiting for all pods to be ready...${NC}"
kubectl wait --for=condition=ready pod -l app.kubernetes.io/instance=${RELEASE_NAME} -n ${NAMESPACE} --timeout=300s

# Setup Debezium connectors
echo -e "${YELLOW}Setting up Debezium connectors...${NC}"
kubectl apply -f ./k8s-manifests/connectors/ -n ${NAMESPACE}

echo -e "${GREEN}Deployment completed successfully!${NC}"

# Show status
echo -e "${YELLOW}Current status:${NC}"
kubectl get pods -n ${NAMESPACE}
kubectl get svc -n ${NAMESPACE}

# Show access URLs
echo -e "${YELLOW}Access URLs:${NC}"
echo "Kafka UI: https://cdc-${ENVIRONMENT}.yourdomain.com"
echo "Grafana: https://cdc-grafana-${ENVIRONMENT}.yourdomain.com"