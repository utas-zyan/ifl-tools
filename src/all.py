#!/usr/bin/env python3

import boto3
import sys
import os
import click
import json
import types
from collections import OrderedDict
from prettytable import PrettyTable
from pprint import pprint


def dprint(*args, **kwargs):
  if os.environ.get("DEBUG") and os.environ["DEBUG"].lower() != "false":
    pprint(*args, stream=sys.stderr, **kwargs)


@click.group()
@click.option('--json', '-J', is_flag=True, help='Output in JSON format', default=False)
@click.option('--weight', '-W', type=int, help='Output weight. 9 is max and 0 is min.', default=8)
@click.pass_context
def cli(ctx, json, weight):
  ctx.ensure_object(dict)
  ctx.obj['JSON'] = json
  ctx.obj['WEIGHT'] = weight


def print_in_table(data: list[OrderedDict]):
  table = PrettyTable()
  table.field_names = data[0].keys()

  for item in data:
    table.add_row(
        [
            item[k] for k in table.field_names
        ])

  # Adjust the table width based on the terminal size
  try:
    terminal_width, _ = os.get_terminal_size()
    table.max_width = terminal_width - 10
  except Exception as e:
    pass # terminal size not available due to some reason, could be under pipe
  table.align = "l"
  print(table)


def print_json(data: OrderedDict):
  print(json.dumps(data, indent=2, default=str))


def collect_data(resource_iterator, fields_weight: dict, filter_weight):
  data = []
  for resource in resource_iterator:
    # print all attributes for resource
    if isinstance(resource, dict):
      dprint(resource)
    else:
      dprint(dir(resource))
    item = OrderedDict()
    for field in fields_weight.keys():
      if isinstance(field, types.FunctionType):
        item[fields_weight[field][0]] = field(resource, fields_weight[field][0])
      elif filter_weight <= fields_weight[field][1]:
        key_chain = field.split('.')
        cur_item = resource
        for key in key_chain:
          if isinstance (cur_item, dict):
            cur_item = cur_item.get(key, 'N/A')
          elif isinstance(cur_item, str):
            cur_item = cur_item
          else:
            cur_item = getattr(cur_item, key, 'N/A')
        item[fields_weight[field][0]] = cur_item
    dprint(item)
    data.append(item)
  return data


def __process(ctx, fields_weights: dict, resource_iterator):
  is_json = ctx.obj['JSON']
  weight = ctx.obj['WEIGHT']
  data = collect_data(resource_iterator, fields_weights, weight)
  if data:
    if is_json:
      print_json(data)
    else:
      print_in_table(data)
  else:
    print('No data found')


def find_tag(resource, tag_key):
  if isinstance(resource, dict):
    tags = resource.get('Tags', [])
  else:
    tags = resource.tags or []
  for tag in tags:
    if tag['Key'] == tag_key:
      return tag['Value']

  return 'N/A'


@cli.command()
@click.pass_context
def ec2(ctx):
    """List EC2 instances."""
    __process(
        ctx,
        OrderedDict({
            'id': ("ID", 9),
            find_tag: ("Name", 8),
            'public_ip_address': ("IP", 8),
            'private_ip_address': ("ip", 8),
            'state.Name': ("STATE", 8),
            'vpc_id': ("VPC", 3),
            'subnet_id': ("Subnet", 3),
            'security_groups': ("SG", 3),
            'instance_type': ("Type", 3),
            'launch_time': ("Time", 2),
            'tags': ("Tags", 6),
            'key_name': ("Key Name", 7),
            'iam_instance_profile.Arn': ("Profile(Role)", 8),
        }),
        boto3.resource('ec2').instances.all()
    )


def list_kms_keys():
  kms = boto3.client('kms')
  key_aliases = {}
  key_aliase_arns = {}
  aliases = kms.list_aliases()
  for alias in aliases['Aliases']:
    dprint(alias)
    if 'TargetKeyId' not in alias:
      continue # must be amazon managed key, forget it
    key_aliases[alias['TargetKeyId']] = alias['AliasName']
    key_aliase_arns[alias['TargetKeyId']] = alias['AliasArn']
  keys = []
  next_marker = None

  while True:
    if next_marker:
      response = kms.list_keys(Limit=100, Marker=next_marker)
    else:
      response = kms.list_keys(Limit=100)
    dprint(response)
    keys.extend(response['Keys'])
    if not response['Truncated']:
      break

    next_marker = response['NextMarker']

  # Fetch additional details for each key
  key_details = []
  for key in keys:
    key_info = kms.describe_key(KeyId=key['KeyId'])['KeyMetadata']
    key_details.append({
        'KeyId': key_info['KeyId'],
        'KeyArn': key_info['Arn'],
        'KeyState': key_info['KeyState'],
        'CreationDate': key_info['CreationDate'],
        'Description': key_info['Description'],
        "Alias": key_aliases.get(key_info['KeyId'], "N/A"),
        "AliasArn": key_aliase_arns.get(key_info['KeyId'], "N/A"),
    })
  dprint(key_details)
  return key_details


@cli.command()
@click.pass_context
def kms(ctx):
    """List KMS keys."""
    __process(
        ctx,
        OrderedDict({
            'KeyId': ("ID", 8),
            'KeyArn': ("Arn", 1),
            'Alias': ("Alias", 9),
            'KeyState': ("State", 7),
            'Description': ("Description", 8),
        }),
        list_kms_keys()
    )


def list_secrets(with_value=False):
  client = boto3.client('secretsmanager')
  secrets = []
  next_token = None
  while True:
    if next_token:
      response = client.list_secrets(MaxResults=100, NextToken=next_token)
    else:
      response = client.list_secrets(MaxResults=100)
    dprint(response)
    secrets.extend(response['SecretList'])
    if 'NextToken' not in response:
      break
    next_token = response['NextToken']
  dprint(secrets)
  if with_value:
    for secret in secrets:
      secret['SecretValue'] = client.get_secret_value(SecretId=secret['ARN'])['SecretString']
  return secrets


@cli.command()
@click.pass_context
def secret(ctx):
    """List Secrets Manager secrets."""
    __process(
        ctx,
        OrderedDict({
            'Name': ("Name", 8),
            'ARN': ("Arn", 1),
            'LastChangedDate': ("LastChangedDate", 7),
            'LastAccessedDate': ("LastAccessedDate", 8),
            'Description': ("Description", 8),
            'SecretValue': ("SecretValue", 2),
        }),
        list_secrets(with_value=ctx.obj['WEIGHT']<=2)
    )


def list_rdss():
  client = boto3.client('rds')
  rdss = []
  next_token = None
  while True:
    if next_token:
      response = client.describe_db_instances(MaxRecords=100, Marker=next_token)
    else:
      response = client.describe_db_instances(MaxRecords=100)
    dprint(response)
    rdss.extend(response['DBInstances'])
    if 'Marker' not in response:
      break
    next_token = response['Marker']
  return rdss


@cli.command()
@click.pass_context
def rds(ctx):
    """List RDS instances."""
    __process(
        ctx,
        OrderedDict({
            'DBInstanceIdentifier': ("Id", 8),
            'DBInstanceArn': ("Arn", 1),
            'ReadReplicaDBInstanceIdentifiers': ("Replica", 8),
            'Endpoint.Address': ("Endpoint", 8),
            'Endpoint.Port': ("Port", 8),
            'StorageEncrypted': ("Encrypted", 7),
            'KmsKeyId': ("KmdKeyId", 7),
            'DBParameterGroups': ("ParameterGroups", 6),
        }),
        list_rdss()
    )


def list_dnss():
  client = boto3.client('route53')
  dnss = []
  hosted_zones = client.list_hosted_zones(MaxItems='100')['HostedZones'] # save pagination. should't be that many
  dprint(hosted_zones)

  for zone in hosted_zones:
    response = client.list_resource_record_sets(HostedZoneId=zone['Id'])
    next_token = None
    while True:
      if next_token:
        response = client.list_resource_record_sets(HostedZoneId=zone['Id'], StartRecordName=next_token)
      else:
        response = client.list_resource_record_sets(HostedZoneId=zone['Id'])
      dprint(response)
      for recordSet in response['ResourceRecordSets']:
        if recordSet['Type'] == 'A':
          dnss.append({
              'Name': recordSet['Name'],
              'Type': recordSet['Type'],
              'Target': recordSet.get("AliasTarget", {}).get('DNSName', 'N/A'),
              'HostedZoneId': zone['Id'],
              'HostedZoneName': zone['Name'],
              'Private': zone.get('Config', {}).get('PrivateZone', False),
          })
        elif recordSet['Type'] == 'CNAME':
          dnss.append({
              'Name': recordSet['Name'],
              'Type': recordSet['Type'],
              'Target': ','.join([x.get('Value') for x in recordSet.get('ResourceRecords', [])]),
              'TTL': recordSet['TTL'],
              'HostedZoneId': zone['Id'],
              'HostedZoneName': zone['Name'],
              'Private': zone.get('Config', {}).get('PrivateZone', False),
          })
      if 'NextRecordName' not in response:
        break
      next_token = response.get('NextRecordName')

      # ignore rest

  dprint(dnss)
  return dnss


@cli.command()
@click.pass_context
def dns(ctx):
    """List Route53 DNS records."""
    __process(
        ctx,
        OrderedDict({
            'Name': ("Name", 8),
            'Type': ("Type", 8),
            'Target': ("Target", 8),
            'TTL': ("TTL", 8),
            'HostedZoneId': ("HostedZoneId", 5),
            'HostedZoneName': ("HostedZoneName", 5),
            'Private': ("Private", 8),
        }),
        list_dnss()
    )


def list_albs():
  # find all ALBs
  client = boto3.client('elbv2')
  albs = []
  next_marker = None
  while True:
    if next_marker:
      response = client.describe_load_balancers(Marker=next_marker)
    else:
      response = client.describe_load_balancers()
    dprint(response)
    albs.extend(response['LoadBalancers'])
    if 'NextMarker' not in response:
      break
    next_marker = response['NextMarker']
  listeners = []
  for alb in albs:
    response = client.describe_listeners(LoadBalancerArn=alb['LoadBalancerArn'])
    for listener in (response['Listeners']):
      listeners.append({
          'ListenerArn': listener['ListenerArn'],
          'LoadBalancerArn': listener['LoadBalancerArn'],
          'DNSName': alb.get('DNSName', 'N/A'),
          'Private': alb.get('Scheme', 'N/A') == 'internal'
      })
  dprint(listeners)
  return listeners


@cli.command()
@click.pass_context
def alb(ctx):
    """List ALB listeners."""
    __process(
        ctx,
        OrderedDict({
            'ListenerArn': ("ListenerArn", 9),
            'LoadBalancerArn': ("LoadBalancerArn", 9),
            'DNSName': ("DNSName", 8),
            'Private': ("Private", 8),
        }),
        list_albs()
    )


def list_roles():
  # find all roles
  client = boto3.client('iam')
  roles = []
  next_marker = None
  while True:
    if next_marker:
      response = client.list_roles(Marker=next_marker)
    else:
      response = client.list_roles()
    dprint(response)
    roles.extend(response['Roles'])
    if 'Marker' not in response:
      break
    next_marker = response['Marker']

  return roles


@cli.command()
@click.pass_context
def role(ctx):
    """List IAM roles."""
    __process(
        ctx,
        OrderedDict({
            'Arn': ("RoleArn", 9),
        }),
        list_roles()
    )


def list_policies():
  # find all policies
  client = boto3.client('iam')
  policies = []
  next_marker = None
  while True:
    if next_marker:
      response = client.list_policies(Marker=next_marker, MaxItems=100)
    else:
      response = client.list_policies(MaxItems=100)
    dprint(response)
    policies.extend(response['Policies'])
    if 'Marker' not in response:
      break
    next_marker = response['Marker']

  return policies


@cli.command()
@click.pass_context
def policy(ctx):
    """List IAM policies."""
    __process(
        ctx,
        OrderedDict({
            'PolicyName': ("Name", 9),
            'Arn': ("Arn", 8),
            'PolicyId': ("PolicyId", 5),
            'Path': ("Path", 7),
            'CreateDate': ("CreateDate", 6),
            'UpdateDate': ("UpdateDate", 6),
            'AttachmentCount': ("Attachments", 8),
            'PermissionsBoundaryUsageCount': ("PermissionsBoundaryUsage", 5),
            'IsAttachable': ("Attachable", 7),
            'Description': ("Description", 6),
        }),
        list_policies()
    )


def list_acms():
  client = boto3.client('acm')
  certs = []
  next_token = None

  while True:
    if next_token:
      response = client.list_certificates(NextToken=next_token)
    else:
      response = client.list_certificates()

    for cert in response['CertificateSummaryList']:
      certs.append({
          'Arn': cert['CertificateArn'],
          'DomainName': cert['DomainName'],
          'Status': cert['Status'],
          'Type': cert['Type'],
          'InUseBy': cert.get('InUseBy', 'N/A'),
      })

    next_token = response.get('NextToken')
    if not next_token:
      break

  return certs


@cli.command()
@click.pass_context
def cert(ctx):
    """List ACM certificates."""
    __process(
        ctx,
        OrderedDict({
            'Arn': ("RoleArn", 9),
            'DomainName': ("DomainName", 8),
            'Status': ("Status", 8),
            'Type': ("Type", 8),
            'InUseBy': ("InUseBy", 6),
        }),
        list_acms()
    )



def list_amis():
  client = boto3.client('ec2')
  amis = []
  next_token = None
  while True:
    # fetch all images
    if next_token:
      response = client.describe_images(Owners=['self'], NextToken=next_token)
    else:
      response = client.describe_images(Owners=['self'])
    dprint(response)
    amis.extend(response['Images'])
    if 'NextToken' not in response:
      break
    next_token = response['NextToken']

  return amis


@cli.command()
@click.pass_context
def ami(ctx):
    """List EC2 AMIs."""
    __process(
        ctx,
        OrderedDict({
            'Name': ("Name", 9),
            'ImageId': ("ImageId", 8),
            'Description': ("Description", 8),
            'SourceInstanceId': ("SourceInstanceId", 6),
            'Architecture': ("Architecture", 6),
            find_tag: ("SourceAMI", 8),
        }),
        list_amis()
    )


def list_params(with_value=False):
  client = boto3.client('ssm')
  params = []

  next_token = None
  while True:
    # fetch all images
    if next_token:
      response = client.describe_parameters(MaxResults=50, NextToken=next_token)
    else:
      response = client.describe_parameters(MaxResults=50)
    dprint(response)
    params.extend(response['Parameters'])
    if 'NextToken' not in response:
      break
    next_token = response['NextToken']
  if with_value:
    for param in params:
      param['Value'] = client.get_parameter(Name=param['Name'], WithDecryption=False)['Parameter']['Value']
  return params


@cli.command()
@click.pass_context
def param(ctx):
    """List SSM parameters."""
    __process(
        ctx,
        OrderedDict({
            'Name': ("Name", 9),
            'Description': ("Description", 8),
            'ARN': ("ARN", 6),
            'Value': ("Value", 2),
        }),
        list_params(with_value=ctx.obj['WEIGHT']<=2)
    )

def list_subnets():
    client = boto3.client('ec2')
    subnets = []
    next_token = None
    
    while True:
        if next_token:
            response = client.describe_subnets(NextToken=next_token)
        else:
            response = client.describe_subnets()
        dprint(response)
        subnets.extend(response['Subnets'])
        if 'NextToken' not in response:
            break
        next_token = response['NextToken']
    
    return subnets

# --- ASG Support ---
def list_asgs():
    client = boto3.client('autoscaling')
    asgs = []
    next_token = None
    while True:
        if next_token:
            response = client.describe_auto_scaling_groups(NextToken=next_token)
        else:
            response = client.describe_auto_scaling_groups()
        dprint(response)
        asgs.extend(response['AutoScalingGroups'])
        next_token = response.get('NextToken')
        if not next_token:
            break
    return asgs

@cli.command()
@click.pass_context
@click.option('--set-desired', type=int, help='Set desired instance count for ASG')
@click.option('--asg-name', type=str, help='Target ASG name for setting desired count')
def asg(ctx, set_desired, asg_name):
    """List ASGs or set desired instance count."""
    client = boto3.client('autoscaling')
    if set_desired is not None and asg_name:
        # Get ASG details
        response = client.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
        if not response['AutoScalingGroups']:
            print(f"ASG '{asg_name}' not found.")
            return
        asg_info = response['AutoScalingGroups'][0]
        max_size = asg_info['MaxSize']
        if set_desired > max_size:
            print(f"Desired ({set_desired}) > MaxSize ({max_size}), updating MaxSize...")
            client.update_auto_scaling_group(AutoScalingGroupName=asg_name, MaxSize=set_desired)
        print(f"Setting desired capacity for ASG '{asg_name}' to {set_desired}")
        client.update_auto_scaling_group(AutoScalingGroupName=asg_name, DesiredCapacity=set_desired)
        print("Done.")
        return
    # Otherwise, just list ASGs
    def asg_tags(resource, key):
        tags = resource.get('Tags', [])
        for tag in tags:
            if tag['Key'] == key:
                return tag['Value']
        return 'N/A'
    __process(
        ctx,
        OrderedDict({
            'AutoScalingGroupName': ("Name", 9),
            asg_tags: ("Env", 8),
            'DesiredCapacity': ("Desired", 8),
            'MinSize': ("Min", 7),
            'MaxSize': ("Max", 7),
            'Instances': ("Instances", 6),
            'LaunchConfigurationName': ("LaunchConfig", 6),
            'LaunchTemplate.LaunchTemplateName': ("LaunchTemplate", 6),
            'VPCZoneIdentifier': ("Subnets", 6),
        }),
        list_asgs()
    )

@cli.command()
@click.pass_context
def subnet(ctx):
    """List EC2 subnets."""
    __process(
        ctx,
        OrderedDict({
            'SubnetId': ("ID", 9),
            find_tag: ("Name", 9),
            'CidrBlock': ("CIDR", 9),
            'VpcId': ("VPC", 9),
            'AvailabilityZone': ("AZ", 8),
            'State': ("State", 7),
            'AvailableIpAddressCount': ("Available IPs", 6),
            'MapPublicIpOnLaunch': ("Auto-assign Public IP", 5),
        }),
        list_subnets()
    )

if __name__ == '__main__':
  cli()
