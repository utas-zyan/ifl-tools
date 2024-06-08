#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 instance-id/name"
  exit 1
fi

if [[ $1 =~ i- ]]; then # looks like i-xxxxx
  aws ssm start-session --target $1
else # find the instance id by the name in the first place
  instance_id=$(aws ec2 describe-instances --filters "Name=tag:Name,Values=$1" --query "Reservations[].Instances[].InstanceId" --output text)
  if [[ -z "$instance_id" ]]; then
    echo "Not finding instance id by name $1"
    exit 1
  fi
  aws ssm start-session --target $instance_id
fi
