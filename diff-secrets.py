#!/usr/local/bin/env python3
import click
import pprint, boto3, os, sys
from collections import OrderedDict
from prettytable import PrettyTable

def dprint(*args, **kwargs):
  if os.environ.get("DEBUG") and os.environ["DEBUG"].lower() != "false":
    pprint(*args, stream=sys.stderr, **kwargs)

def list_all_profiles():
  session=boto3.Session()
  return list(session._session.full_config.get('profiles', {}).keys())

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


def get_list_of_secrets(profile, width=80):
  session=boto3.Session(profile_name=profile)
  client = session.client('secretsmanager')
  # list all secrets with pagination
  secrets = []
  paginator = client.get_paginator('list_secrets')
  for page in paginator.paginate():
    secrets.extend(page['SecretList'])

  keys = [secret['Name'] for secret in secrets]
  details = {
    item['Name']: item for item in secrets
  }

  return keys, details

@click.command(help='Compare secrets list with the multiple AWS profiles.')
@click.argument('profiles', type=str, nargs=-1)
@click.option('--width', "-W", type=int, help='limit max width of secret', default=80)
def compare_secrets(profiles, width):
  # Add your code here to compare secrets list with the two AWS profiles
  if not profiles:
    profiles=list_all_profiles()
    if not profiles:
      print("No aws profiles found.")
      exit(1)
    print("Select more than one profiles from ", ' , '.join(profiles))
    exit(0)
  all_keys = []
  all_details = {}
  for profile in profiles:
    keys, details = get_list_of_secrets(profile, width)
    all_keys.extend(keys)
    all_details[profile]=details
  dprint(keys)
  data = [
    {
      profile: all_details[profile].get(key, {}).get('Name', 'N/A')[-width:]
      for profile in profiles  
    }
  for key in sorted(list(set(all_keys)))]
  print_in_table(
    data
  )

if __name__ == '__main__':
  compare_secrets()

