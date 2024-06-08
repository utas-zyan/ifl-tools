#!/bin/bash
if [ -z "$1" ]; then
  echo "Usage: $0 <eks-cluster-name>"
  echo "the eks clusters from current profiles are:"
  aws eks list-clusters --output text
  exit 1
fi
aws eks  update-kubeconfig --name $1

