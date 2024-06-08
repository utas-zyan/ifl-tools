#!/usr/bin/env python3

import boto3
import sys
import os
import click
import json
import types
from collections import OrderedDict
from prettytable import PrettyTable


def debug_print(*args, **kwargs):
  if os.environ.get("DEBUG") and os.environ["DEBUG"].lower() != "false":
    print(*args, file=sys.stderr, **kwargs)


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
  terminal_width, _ = os.get_terminal_size()
  table.max_width = terminal_width - 10
  print(table)


def print_json(data: OrderedDict):
  print(json.dumps(data, indent=2))


def collect_data(resource_iterator, fields_weight: dict, filter_weight):
  data = []
  for resource in resource_iterator:
    # print all attributes for resource
    # if __debug_mode():
    #   print(dir(resource))
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
    debug_print(item)
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
  for tag in resource.tags or []:
    if tag['Key'] == tag_key:
      return tag['Value']
  return 'N/A'


@cli.command()
@click.pass_context
def ec2(ctx):
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

      }),
      boto3.resource('ec2').instances.all()
  )


def list_kms_keys():
  kms = boto3.client('kms')
  key_aliases = {}
  key_aliase_arns = {}
  aliases = kms.list_aliases()
  for alias in aliases['Aliases']:
    debug_print(alias)
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
    debug_print(response)
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
  debug_print(key_details)
  return key_details


@cli.command()
@click.pass_context
def kms(ctx):
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


def list_secrets():
  client = boto3.client('secretsmanager')
  secrets = []
  next_token = None
  while True:
    if next_token:
      response = client.list_secrets(MaxResults=100, NextToken=next_token)
    else:
      response = client.list_secrets(MaxResults=100)
    debug_print(response)
    secrets.extend(response['SecretList'])
    if 'NextToken' not in response:
      break
    next_token = response['NextToken']
  debug_print(secrets)
  return secrets


@cli.command()
@click.pass_context
def secret(ctx):
  __process(
      ctx,
      OrderedDict({
          'Name': ("Name", 8),
          'ARN': ("Arn", 1),
          'LastChangedDate': ("LastChangedDate", 7),
          'LastAccessedDate': ("LastAccessedDate", 8),
          'Description': ("Description", 8),
      }),
      list_secrets()
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
    debug_print(response)
    rdss.extend(response['DBInstances'])
    if 'Marker' not in response:
      break
    next_token = response['Marker']
  return rdss


@cli.command()
@click.pass_context
def rds(ctx):
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
  debug_print(hosted_zones)

  for zone in hosted_zones:
    response = client.list_resource_record_sets(HostedZoneId=zone['Id'])
    debug_print(response)
    for recordSet in response['ResourceRecordSets']:
      print(recordSet, '--------')
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
      # ignore rest

  debug_print(dnss)
  return dnss


@cli.command()
@click.pass_context
def dns(ctx):
  __process(
      ctx,
      OrderedDict({
          'Name': ("Name", 8),
          'Type': ("Type", 8),
          'Target': ("Target", 8),
          'TTL': ("TTL", 8),
          'HostedZoneId': ("HostedZoneId", 5),
          'HostedZoneName': ("HostedZoneName", 5),
          'Private': ("Private", 5),
      }),
      list_dnss()
  )


if __name__ == '__main__':
  cli()
