#!/bin/bash

set -e

# Configuration
AWS_REGION=${AWS_REGION:-us-west-2}
CLUSTER_NAME=${CLUSTER_NAME:-cdc-cluster}
NODE_GROUP_NAME=${NODE_GROUP_NAME:-cdc-nodes}
ENVIRONMENT=${1:-dev}

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Setting up infrastructure for ${ENVIRONMENT} environment${NC}"

# Function to create EKS cluster
create_eks_cluster() {
    local env=$1
    local cluster_name="${CLUSTER_NAME}-${env}"
    
    echo -e "${YELLOW}Creating EKS cluster: ${cluster_name}${NC}"
    
    # Cluster configuration based on environment
    case $env in
        "dev")
            NODE_INSTANCE_TYPE="t3.medium"
            MIN_NODES=1
            MAX_NODES=3
            DESIRED_NODES=2
            ;;
        "staging")
            NODE_INSTANCE_TYPE="t3.large"
            MIN_NODES=2
            MAX_NODES=5
            DESIRED_NODES=3
            ;;
        "prod")
            NODE_INSTANCE_TYPE="m5.xlarge"
            MIN_NODES=3
            MAX_NODES=10
            DESIRED_NODES=5
            ;;
    esac
    
    # Create cluster
    eksctl create cluster \
        --name $cluster_name \
        --region $AWS_REGION \
        --version 1.27 \
        --nodegroup-name $NODE_GROUP_NAME \
        --node-type $NODE_INSTANCE_TYPE \
        --nodes $DESIRED_NODES \
        --nodes-min $MIN_NODES \
        --nodes-max $MAX_NODES \
        --managed \
        --with-oidc \
        --ssh-access \
        --ssh-public-key ~/.ssh/id_rsa.pub \
        --enable-ssm \
        --asg-access \
        --external-dns-access \
        --full-ecr-access \
        --appmesh-access \
        --alb-ingress-access
    
    echo -e "${GREEN}EKS cluster ${cluster_name} created successfully${NC}"
}

# Function to setup storage classes
setup_storage() {
    echo -e "${YELLOW}Setting up storage classes${NC}"
    kubectl apply -f k8s-manifests/base/storage/storage-classes.yaml
    
    # Create additional storage for production
    if [ "$ENVIRONMENT" = "prod" ]; then
        cat <<EOF | kubectl apply -f -
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: kafka-nvme-storage
provisioner: kubernetes.io/aws-ebs
parameters:
  type: io2
  iops: "20000"
  throughput: "1000"
  encrypted: "true"
volumeBindingMode: WaitForFirstConsumer
allowVolumeExpansion: true
reclaimPolicy: Retain
EOF
    fi
}

# Function to setup networking
setup_networking() {
    echo -e "${YELLOW}Setting up networking components${NC}"
    
    # Install AWS Load Balancer Controller
    curl -o iam_policy.json https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.5.4/docs/install/iam_policy.json
    
    aws iam create-policy \
        --policy-name AWSLoadBalancerControllerIAMPolicy \
        --policy-document file://iam_policy.json || true
    
    eksctl create iamserviceaccount \
        --cluster=${CLUSTER_NAME}-${ENVIRONMENT} \
        --namespace=kube-system \
        --name=aws-load-balancer-controller \
        --role-name "AmazonEKSLoadBalancerControllerRole-${ENVIRONMENT}" \
        --attach-policy-arn=arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/AWSLoadBalancerControllerIAMPolicy \
        --approve
    
    # Install ALB Controller
    helm repo add eks https://aws.github.io/eks-charts
    helm repo update
    
    helm install aws-load-balancer-controller eks/aws-load-balancer-controller \
        -n kube-system \
        --set clusterName=${CLUSTER_NAME}-${ENVIRONMENT} \
        --set serviceAccount.create=false \
        --set serviceAccount.name=aws-load-balancer-controller
    
    # Install NGINX Ingress Controller
    helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
    helm install ingress-nginx ingress-nginx/ingress-nginx \
        --namespace ingress-nginx \
        --create-namespace \
        --set controller.service.type=LoadBalancer \
        --set controller.metrics.enabled=true
}

# Function to setup secrets
setup_secrets() {
    echo -e "${YELLOW}Setting up secrets${NC}"
    
    # Create namespaces first
    kubectl apply -f k8s-manifests/base/namespaces/
    
    # Generate random passwords for different environments
    case $ENVIRONMENT in
        "dev")
            DB_PASSWORD="dev-password"
            KAFKA_PASSWORD="dev-kafka"
            ;;
        "staging")
            DB_PASSWORD=$(openssl rand -base64 32)
            KAFKA_PASSWORD=$(openssl rand -base64 32)
            ;;
        "prod")
            DB_PASSWORD=$(openssl rand -base64 64)
            KAFKA_PASSWORD=$(openssl rand -base64 64)
            echo "PRODUCTION PASSWORDS GENERATED - SAVE THESE SECURELY:"
            echo "Database Password: $DB_PASSWORD"
            echo "Kafka Password: $KAFKA_PASSWORD"
            ;;
    esac
    
    # Create database secrets
    kubectl create secret generic database-credentials \
        --namespace=cdc-system-${ENVIRONMENT} \
        --from-literal=postgres-username=debezium \
        --from-literal=postgres-password=$DB_PASSWORD \
        --from-literal=mysql-username=debezium \
        --from-literal=mysql-password=$DB_PASSWORD \
        --dry-run=client -o yaml | kubectl apply -f -
    
    # Create Kafka secrets for production
    if [ "$ENVIRONMENT" = "prod" ]; then
        kubectl create secret generic kafka-credentials \
            --namespace=cdc-system-prod \
            --from-literal=sasl-username=admin \
            --from-literal=sasl-password=$KAFKA_PASSWORD \
            --dry-run=client -o yaml | kubectl apply -f -
        
        # Generate SSL certificates (self-signed for demo)
        openssl req -new -x509 -keyout kafka.key -out kafka.crt -days 365 -nodes \
            -subj "/C=US/ST=CA/L=SF/O=Company/CN=kafka.cdc-system-prod.svc.cluster.local"
        
        kubectl create secret tls kafka-ssl-credentials \
            --namespace=cdc-system-prod \
            --cert=kafka.crt \
            --key=kafka.key \
            --dry-run=client -o yaml | kubectl apply -f -
        
        rm kafka.key kafka.crt
    fi
}

# Function to setup monitoring
setup_monitoring() {
    echo -e "${YELLOW}Setting up monitoring stack${NC}"
    
    # Create monitoring namespace
    kubectl create namespace cdc-monitoring --dry-run=client -o yaml | kubectl apply -f -
    
    # Install Prometheus Operator
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm repo update
    
    helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack \
        --namespace cdc-monitoring \
        --set prometheus.prometheusSpec.retention=30d \
        --set prometheus.prometheusSpec.storageSpec.volumeClaimTemplate.spec.storageClassName=fast-ssd \
        --set prometheus.prometheusSpec.storageSpec.volumeClaimTemplate.spec.resources.requests.storage=100Gi \
        --set grafana.persistence.enabled=true \
        --set grafana.persistence.storageClassName=standard-ssd \
        --set grafana.persistence.size=20Gi
    
    # Apply custom Prometheus config
    kubectl apply -f k8s-manifests/monitoring/
    
    # Install Kafka Exporter
    kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kafka-exporter
  namespace: cdc-monitoring
spec:
  replicas: 1
  selector:
    matchLabels:
      app: kafka-exporter
  template:
    metadata:
      labels:
        app: kafka-exporter
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9308"
    spec:
      containers:
      - name: kafka-exporter
        image: danielqsj/kafka-exporter:latest
        args:
        - --kafka.server=kafka.cdc-system-${ENVIRONMENT}:9092
        ports:
        - containerPort: 9308
---
apiVersion: v1
kind: Service
metadata:
  name: kafka-exporter
  namespace: cdc-monitoring
spec:
  selector:
    app: kafka-exporter
  ports:
  - port: 9308
    targetPort: 9308
EOF
}

# Main execution
main() {
    echo -e "${GREEN}Starting infrastructure setup for ${ENVIRONMENT}${NC}"
    
    # Check prerequisites
    command -v eksctl >/dev/null 2>&1 || { echo -e "${RED}eksctl is required${NC}"; exit 1; }
    command -v kubectl >/dev/null 2>&1 || { echo -e "${RED}kubectl is required${NC}"; exit 1; }
    command -v helm >/dev/null 2>&1 || { echo -e "${RED}helm is required${NC}"; exit 1; }
    command -v aws >/dev/null 2>&1 || { echo -e "${RED}aws cli is required${NC}"; exit 1; }
    
    # Create EKS cluster
    create_eks_cluster $ENVIRONMENT
    
    # Setup components
    setup_storage
    setup_networking
    setup_secrets
    setup_monitoring
    
    echo -e "${GREEN}Infrastructure setup completed successfully!${NC}"
    echo -e "${YELLOW}Next steps:${NC}"
    echo "1. Run: kubectl get nodes"
    echo "2. Run: kubectl get pods -A"
    echo "3. Deploy CDC system: ./scripts/deploy.sh $ENVIRONMENT"
}

# Run main function
main

### scripts/create-secrets.sh
```bash
#!/bin/bash

set -e

ENVIRONMENT=${1:-dev}
NAMESPACE="cdc-system-${ENVIRONMENT}"

# Generate secure passwords
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

# Create database secrets
DB_POSTGRES_PASSWORD=$(generate_password)
DB_MYSQL_PASSWORD=$(generate_password)
KAFKA_PASSWORD=$(generate_password)
SCHEMA_REGISTRY_PASSWORD=$(generate_password)

echo "Creating secrets for environment: $ENVIRONMENT"

# Database credentials
kubectl create secret generic database-credentials \
    --namespace=$NAMESPACE \
    --from-literal=postgres-username=debezium \
    --from-literal=postgres-password=$DB_POSTGRES_PASSWORD \
    --from-literal=mysql-username=debezium \
    --from-literal=mysql-password=$DB_MYSQL_PASSWORD \
    --dry-run=client -o yaml | kubectl apply -f -

# Kafka credentials
kubectl create secret generic kafka-credentials \
    --namespace=$NAMESPACE \
    --from-literal=username=admin \
    --from-literal=password=$KAFKA_PASSWORD \
    --dry-run=client -o yaml | kubectl apply -f -

# Schema Registry credentials
kubectl create secret generic schema-registry-credentials \
    --namespace=$NAMESPACE \
    --from-literal=username=schema-registry \
    --from-literal=password=$SCHEMA_REGISTRY_PASSWORD \
    --dry-run=client -o yaml | kubectl apply -f -

# SSL/TLS certificates for production
if [ "$ENVIRONMENT" = "prod" ]; then
    # Generate CA certificate
    openssl genrsa -out ca-key.pem 4096
    openssl req -new -x509 -key ca-key.pem -out ca-cert.pem -days 3650 \
        -subj "/C=US/ST=CA/L=SF/O=CDC-System/CN=ca.cdc-system.local"
    
    # Generate server certificate
    openssl genrsa -out server-key.pem 4096
    openssl req -new -key server-key.pem -out server-csr.pem \
        -subj "/C=US/ST=CA/L=SF/O=CDC-System/CN=*.cdc-system-prod.svc.cluster.local"
    
    openssl x509 -req -in server-csr.pem -CA ca-cert.pem -CAkey ca-key.pem \
        -CAcreateserial -out server-cert.pem -days 365 \
        -extensions v3_req -extfile <(echo "
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = *.cdc-system-prod.svc.cluster.local
DNS.2 = kafka
DNS.3 = kafka-connect
DNS.4 = schema-registry
")
    
    # Create Kubernetes TLS secret
    kubectl create secret tls kafka-tls \
        --namespace=$NAMESPACE \
        --cert=server-cert.pem \
        --key=server-key.pem \
        --dry-run=client -o yaml | kubectl apply -f -
    
    kubectl create secret generic kafka-ca \
        --namespace=$NAMESPACE \
        --from-file=ca-cert.pem \
        --dry-run=client -o yaml | kubectl apply -f -
    
    # Cleanup
    rm -f *.pem *.csr *.srl
fi

# Store passwords securely (for production)
if [ "$ENVIRONMENT" = "prod" ]; then
    cat > secrets-${ENVIRONMENT}.env <<EOF
# PRODUCTION SECRETS - STORE SECURELY
DB_POSTGRES_PASSWORD=${DB_POSTGRES_PASSWORD}
DB_MYSQL_PASSWORD=${DB_MYSQL_PASSWORD}
KAFKA_PASSWORD=${KAFKA_PASSWORD}
SCHEMA_REGISTRY_PASSWORD=${SCHEMA_REGISTRY_PASSWORD}
EOF
    chmod 600 secrets-${ENVIRONMENT}.env
    echo "Secrets stored in secrets-${ENVIRONMENT}.env - KEEP THIS FILE SECURE!"
fi

echo "Secrets created successfully for ${ENVIRONMENT} environment"

### scripts/backup.sh
```bash
#!/bin/bash

set -e

ENVIRONMENT=${1:-prod}
NAMESPACE="cdc-system-${ENVIRONMENT}"
BACKUP_DIR="backups/$(date +%Y%m%d-%H%M%S)"
S3_BUCKET=${S3_BUCKET:-"cdc-system-backups"}

mkdir -p $BACKUP_DIR

echo "Starting backup for environment: $ENVIRONMENT"

# Backup Kafka topics
echo "Backing up Kafka topics..."
kubectl exec -it kafka-0 -n $NAMESPACE -- kafka-topics \
    --bootstrap-server localhost:9092 \
    --list > $BACKUP_DIR/kafka-topics.txt

# Backup connector configurations
echo "Backing up connector configurations..."
kubectl exec -it kafka-connect-0 -n $NAMESPACE -- \
    curl -s http://localhost:8083/connectors | \
    jq -r '.[]' | while read connector; do
        kubectl exec -it kafka-connect-0 -n $NAMESPACE -- \
            curl -s http://localhost:8083/connectors/$connector/config \
            > $BACKUP_DIR/connector-${connector}.json
    done

# Backup Kubernetes resources
echo "Backing up Kubernetes resources..."
kubectl get all -n $NAMESPACE -o yaml > $BACKUP_DIR/k8s-resources.yaml
kubectl get configmaps -n $NAMESPACE -o yaml > $BACKUP_DIR/configmaps.yaml
kubectl get secrets -n $NAMESPACE -o yaml > $BACKUP_DIR/secrets.yaml
kubectl get persistentvolumes -o yaml > $BACKUP_DIR/persistent-volumes.yaml

# Backup Helm releases
echo "Backing up Helm releases..."
helm list -n $NAMESPACE -o yaml > $BACKUP_DIR/helm-releases.yaml

# Create tar archive
tar -czf $BACKUP_DIR.tar.gz $BACKUP_DIR/

# Upload to S3 if configured
if command -v aws &> /dev/null && [ -n "$S3_BUCKET" ]; then
    echo "Uploading backup to S3..."
    aws s3 cp $BACKUP_DIR.tar.gz s3://$S3_BUCKET/cdc-system/$ENVIRONMENT/
    echo "Backup uploaded to s3://$S3_BUCKET/cdc-system/$ENVIRONMENT/"
fi

echo "Backup completed: $BACKUP_DIR.tar.gz"

# Cleanup old backups (keep last 7 days)
find backups/ -name "*.tar.gz" -type f -mtime +7 -delete

### infrastructure/terraform/main.tf
```terraform
# Terraform configuration for CDC System infrastructure
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
  }
  
  backend "s3" {
    bucket = "cdc-terraform-state"
    key    = "cdc-system/terraform.tfstate"
    region = "us-west-2"
  }
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
  default     = "cdc-cluster"
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}

locals {
  cluster_name = "${var.cluster_name}-${var.environment}"
  
  node_groups = {
    dev = {
      instance_types = ["t3.medium"]
      min_size      = 1
      max_size      = 3
      desired_size  = 2
    }
    staging = {
      instance_types = ["t3.large"]
      min_size      = 2
      max_size      = 5
      desired_size  = 3
    }
    prod = {
      instance_types = ["m5.xlarge", "m5.2xlarge"]
      min_size      = 3
      max_size      = 10
      desired_size  = 5
    }
  }
}

# VPC Configuration
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "cdc-vpc-${var.environment}"
  cidr = "10.0.0.0/16"

  azs             = ["${var.region}a", "${var.region}b", "${var.region}c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway = true
  enable_vpn_gateway = true
  enable_dns_hostnames = true
  enable_dns_support = true

  tags = {
    Environment = var.environment
    Project     = "cdc-system"
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
  }

  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
  }
}

# EKS Cluster
module "eks" {
  source = "terraform-aws-modules/eks/aws"
  version = "~> 19.0"

  cluster_name    = local.cluster_name
  cluster_version = "1.27"

  vpc_id                         = module.vpc.vpc_id
  subnet_ids                     = module.vpc.private_subnets
  cluster_endpoint_public_access = true

  manage_aws_auth_configmap = true

  eks_managed_node_groups = {
    main = {
      name = "cdc-nodes"
      
      instance_types = local.node_groups[var.environment].instance_types
      min_size       = local.node_groups[var.environment].min_size
      max_size       = local.node_groups[var.environment].max_size
      desired_size   = local.node_groups[var.environment].desired_size

      disk_size = var.environment == "prod" ? 100 : 50
      
      labels = {
        Environment = var.environment
        NodeGroup   = "cdc-nodes"
      }

      taints = var.environment == "prod" ? [
        {
          key    = "dedicated"
          value  = "kafka"
          effect = "NO_SCHEDULE"
        }
      ] : []

      tags = {
        Environment = var.environment
      }
    }
  }

  tags = {
    Environment = var.environment
    Project     = "cdc-system"
  }
}

# Additional storage for production
resource "aws_ebs_volume" "kafka_storage" {
  count = var.environment == "prod" ? 3 : 0
  
  availability_zone = data.aws_availability_zones.available.names[count.index]
  size              = 500
  type              = "io2"
  iops              = 10000
  encrypted         = true

  tags = {
    Name        = "kafka-storage-${count.index}"
    Environment = var.environment
    Project     = "cdc-system"
  }
}

# RDS for metadata storage (production only)
resource "aws_db_instance" "metadata" {
  count = var.environment == "prod" ? 1 : 0

  identifier = "cdc-metadata-${var.environment}"
  
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.r5.large"
  
  allocated_storage     = 100
  max_allocated_storage = 1000
  storage_encrypted     = true
  
  db_name  = "cdcmetadata"
  username = "cdcadmin"
  password = var.db_password
  
  vpc_security_group_ids = [aws_security_group.rds[0].id]
  db_subnet_group_name   = aws_db_subnet_group.main[0].name
  
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "Sun:04:00-Sun:05:00"
  
  deletion_protection = true
  skip_final_snapshot = false
  
  tags = {
    Environment = var.environment
    Project     = "cdc-system"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

# Outputs
output "cluster_endpoint" {
  description = "Endpoint for EKS control plane"
  value       = module.eks.cluster_endpoint
}

output "cluster_name" {
  description = "EKS cluster name"
  value       = module.eks.cluster_name
}

output "vpc_id" {
  description = "ID of the VPC"
  value       = module.vpc.vpc_id
}
```# Hệ thống CDC với Kubernetes & Helm Charts

## Kiến trúc tổng quan

```mermaid
graph TB
    subgraph "Source Systems"
        PG[(PostgreSQL)]
        MY[(MySQL)]
        MG[(MongoDB)]
    end
    
    subgraph "CDC Layer"
        DZ[Debezium Connectors]
        KC[Kafka Connect]
    end
    
    subgraph "Message Broker"
        KF[Kafka Cluster]
        ZK[Zookeeper]
    end
    
    subgraph "Processing Layer"
        KS[Kafka Streams]
        SP[Spark Streaming]
    end
    
    subgraph "Target Systems"
        ES[(Elasticsearch)]
        DW[(Data Warehouse)]
        CH[(ClickHouse)]
        RD[(Redis)]
    end
    
    subgraph "Monitoring & Management"
        PR[Prometheus]
        GR[Grafana]
        KU[Kafka UI]
        SC[Schema Registry]
    end
    
    PG --> DZ
    MY --> DZ
    MG --> DZ
    DZ --> KC
    KC --> KF
    ZK --> KF
    KF --> KS
    KF --> SP
    KS --> ES
    KS --> DW
    SP --> CH
    KF --> RD
    
    KF --> PR
    KC --> PR
    PR --> GR
    KF --> KU
    KC --> SC