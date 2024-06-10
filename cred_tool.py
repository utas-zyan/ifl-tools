#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import boto3
import os
import sys
from pprint import pprint
import urllib
import json
import click


@click.group()
@click.pass_context
def cli(ctx):
  ctx.ensure_object(dict)


def dprint(*args, **kwargs):
  if os.environ.get("DEBUG") and os.environ["DEBUG"].lower() != "false":
    pprint(*args, stream=sys.stderr, **kwargs)


def session_is_temporary(session):
  if session.get_credentials().token:
    return True


@click.command()
@click.option('--role-arn', '-R', required=False, help='The ARN of the IAM role to assume')
def get_login_url(role_arn):
  session = boto3.Session()
  if session_is_temporary(session):
    print("Temporary session, not implemented yet.")
  else:
    if not role_arn:
      dprint("No role ARN provided, must provide a role to assume to.")
      exit(1)
    login_url = get_federated_login_url(session, role_arn=role_arn)
    print(login_url)


def find_original_credential(session):
  # find the role name of the session
  print(session.get_credentials().access_key)
  identity_info = sts_client = session.client('sts').get_caller_identity()
  assumed_role = identity_info.get('Arn')
  print(assumed_role)
  print(session._session.full_config)
  if session.profile_name:
    return session.profile_name
  else:
    return session.get_credentials().access_key


def get_federated_login_url(session, role_arn):
  sts_client = session.client('sts')

  # Request a session token
  response = sts_client.assume_role(
      RoleArn=role_arn,
      RoleSessionName='Assumed'
  )

  # Extract credentials
  credentials = response['Credentials']
  session_id = credentials['AccessKeyId']
  session_key = credentials['SecretAccessKey']
  session_token = credentials['SessionToken']

  # Create the sign-in URL
  signin_url = 'https://signin.aws.amazon.com/federation'
  signin_url += '?Action=getSigninToken'
  signin_url += '&Session=' + urllib.parse.quote_plus(
      '{"sessionId":"' + session_id
      + '","sessionKey":"' + session_key
      + '","sessionToken":"' + session_token + '"}'
  )

  # Get the sign-in token
  response = urllib.request.urlopen(signin_url)
  signin_token = json.loads(response.read())['SigninToken']

  # Construct the login URL
  login_url = 'https://signin.aws.amazon.com/federation'
  login_url += '?Action=login'
  login_url += '&Issuer=Example.org'
  login_url += '&Destination=' + urllib.parse.quote_plus('https://console.aws.amazon.com/')
  login_url += '&SigninToken=' + signin_token

  return login_url


def create_session(profile):
  if profile:
    session = boto3.Session(profile_name=profile)
  else:
    session = boto3.Session()
  return session


@cli.command()
@click.pass_context
@click.option('--profile', '-P', help='Which profile to use. If not specified, then use current one', default=None)
@click.option('--role-arn', '-R', help='Which role to use based on the profile', default=None)
def login(ctx, profile, role_arn):
  if not role_arn:
    if 'AWS_ACCESS_KEY_ID' in os.environ:
      print("Cannot find login URL for credentials.")
      exit(1)
    session = create_session(profile)
    # even if not defined, the profile is still "default"
    session_config = session._session.full_config.get('profiles', {}).get(session.profile_name)
    if not session_config:
      print("Cannot find profile config. Exiting.")
      exit(1)

    if session_config.get('sso_start_url'):
      print("Login using SSO URL:", session_config.get('sso_start_url'))
      exit(0)
    if session_config.get('role_arn') and session_config.get('source_profile'): # we can use it
      login_url = get_federated_login_url(boto3.Session(profile_name=session_config.get('source_profile')), session_config.get('role_arn'))
      print("Login using URL:", login_url)
    else:
      print("Cannot find login URL for credentials.")
      exit(1)
  else:
    session = create_session(profile)
    login_url = get_federated_login_url(session, role_arn)
    print(login_url)


@cli.command()
@click.option('--profile', '-P', help='Which profile to use. If not specified, then use current one', default=None)
@click.option('--role-arn', '-R', help='Which role to use based on the profile', default=None)
@click.pass_context
def export(ctx, profile, role_arn):
  if not role_arn:
    session = create_session(profile)
    credentials = session.get_credentials()
    creds = credentials.get_frozen_credentials()

    if creds.token:
      print(f'export AWS_ACCESS_KEY_ID={creds.access_key}')
      print(f'export AWS_SECRET_ACCESS_KEY={creds.secret_key}')
      print(f'export AWS_SESSION_TOKEN={creds.token}')
    else:
      # If the credentials are not temporary, generate temporary credentials
      sts = boto3.client('sts')
      temp_creds = sts.get_session_token()['Credentials']
      print(f'export AWS_ACCESS_KEY_ID={temp_creds["AccessKeyId"]}')
      print(f'export AWS_SECRET_ACCESS_KEY={temp_creds["SecretAccessKey"]}')
      print(f'export AWS_SESSION_TOKEN={temp_creds["SessionToken"]}')
  else:
    session = create_session(profile)
    client = session.client('sts')
    response = client.assume_role(
        RoleArn=role_arn,
        RoleSessionName='Assumed'
    )
    print(f'export AWS_ACCESS_KEY_ID={response["Credentials"]["AccessKeyId"]}')
    print(f'export AWS_SECRET_ACCESS_KEY={response["Credentials"]["SecretAccessKey"]}')
    print(f'export AWS_SESSION_TOKEN={response["Credentials"]["SessionToken"]}')
    

if __name__ == '__main__':
  cli()
