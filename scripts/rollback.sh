#!/bin/bash

set -e

NAMESPACE="cdc-system"
RELEASE_NAME="cdc-system"
REVISION=${1:-}

if [ -z "$REVISION" ]; then
    echo "Available revisions:"
    helm history ${RELEASE_NAME} -n ${NAMESPACE}
    exit 1
fi

echo "Rolling back to revision ${REVISION}..."
helm rollback ${RELEASE_NAME} ${REVISION} -n ${NAMESPACE}

echo "Rollback completed successfully!"