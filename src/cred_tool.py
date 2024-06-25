#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import boto3
import os
import sys
from pprint import pprint
import urllib
import json
import click
import requests


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


allow_all_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "*",
            "Effect": "Allow",
            "Resource": "*"
        }
    ]
}


def aws_signin_url(base_profile=None, credentials={}, assumed_role=None, time_to_live=None, session_name="Assume", ):
  session = boto3.Session(profile_name=base_profile)
  sts_client = session.client('sts')
  print(credentials)
  if not credentials:
    if not assumed_role:  # using the profile directly
      if not time_to_live:
        time_to_live = 129600
      else:
        time_to_live = int(time_to_live)
      credentials = sts_client.get_federation_token(
          Name=session_name,
          DurationSeconds=time_to_live,
          Policy=json.dumps(allow_all_policy)
      ).get('Credentials')
    else:
      if not time_to_live:
        time_to_live = 43200
      else:
        time_to_live = int(time_to_live)
      credentials = sts_client.assume_role(
          RoleArn=assumed_role,
          RoleSessionName=session_name
      ).get('Credentials')
  else:
    if 'Credentials' in credentials:
      credentials = credentials.get('Credentials')
  # Format credentials into JSON
  json_string_with_temp_credentials = '{'
  json_string_with_temp_credentials += '"sessionId":"' + \
      credentials.get('AccessKeyId') + '",'
  json_string_with_temp_credentials += '"sessionKey":"' + \
      credentials.get('SecretAccessKey') + '",'
  json_string_with_temp_credentials += '"sessionToken":"' + \
      credentials.get('SessionToken') + '"'
  json_string_with_temp_credentials += '}'

  # Make request to AWS federation endpoint to get sign-in token. Construct the parameter string with
  # the sign-in action request, a 12-hour session duration, and the JSON document with temporary credentials
  # as parameters.
  if not assumed_role:
    request_parameters = '?Action=getSigninToken&Session={cred_json}'.format(
        cred_json=urllib.parse.quote(json_string_with_temp_credentials),
    )
  else:
    request_parameters = '?Action=getSigninToken&SessionDuration={duration_sec}&Session={cred_json}'.format(
        duration_sec=time_to_live,
        cred_json=urllib.parse.quote(json_string_with_temp_credentials),
    )
  request_url = "https://signin.aws.amazon.com/federation" + request_parameters
  r = requests.get(request_url)
  # Returns a JSON document with a single element named SigninToken.
  signin_token = r.json()

  # Create URL where users can use the sign-in token to sign in to
  # the console. This URL must be used within 15 minutes after the
  # sign-in token was issued.
  request_parameters = '?Action=login&Issuer={issuer}&Destination={destination}&SigninToken={signin_token}'.format(
      issuer=session_name,
      destination=urllib.parse.quote("https://console.aws.amazon.com/"),
      signin_token=signin_token["SigninToken"]
  )
  request_url = "https://signin.aws.amazon.com/federation" + request_parameters
  return request_url


@cli.command()
@click.pass_context
@click.option('--profile', '-P', help='Which profile to use. If not specified, then use current one', default=None)
@click.option('--role-arn', '-R', help='Which role to use based on the profile', default=None)
def login(ctx, profile, role_arn):
  if role_arn:
    url = aws_signin_url(base_profile=profile, assumed_role=role_arn)
    print(url)
    exit(0)
  else:
    session = create_session(profile)
    session_config = session._session.full_config.get('profiles', {}).get(session.profile_name)
    dprint('Session Config:--' + str(session_config))
    if not session_config.keys():
      credentials = session.get_credentials()
      if credentials:
        url = aws_signin_url(credentials=credentials)
        print(url)
        exit(0)
      else:
        print("Cannot find profile config. Exiting.")
        exit(1)
    else:
      if session_config.get('sso_start_url'):
        print("Login using SSO URL:", session_config.get('sso_start_url'))
        exit(0)
      elif session_config.get('role_arn') and session_config.get('source_profile'):
        # ok let's dig a bit more and find a chance if we can  still figure more out from the profile config
        profile = session_config.get('source_profile')
        role_arn = session_config.get('role_arn')
        dprint(f"Use Profile: {profile}, Role ARN: {role_arn}")
        url = aws_signin_url(base_profile=profile, assumed_role=role_arn)
        print(url)
        exit(0)
      else:
        dprint(session.get_credentials())
        if session.get_credentials().token:
          credentials = {
              'AccessKeyId': session.get_credentials().access_key,
              'SecretAccessKey': session.get_credentials().secret_key,
              'SessionToken': session.get_credentials().token
          }
          url = aws_signin_url(credentials=credentials)
          print(url)
          exit(0)
        else:
          identity = session.client('sts').get_caller_identity()
          print(f"https://{identity['Account']}.signin.aws.amazon.com/console  USER: {identity['Arn'].split('/')[-1]}")
          exit(0)


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


@cli.command()
@click.option('--profile', '-P', help='Which profile to use. If not specified, then use current one', default=None)
@click.option('--role-arn', '-R', help='Which role to use based on the profile', default=None)
@click.pass_context
def cred(ctx, profile, role_arn):
  if not role_arn:
    session = create_session(profile)
    credentials = session.get_credentials()
    creds = credentials.get_frozen_credentials()
    print("[default]")
    if creds.token:
      print(f'aws_access_key_id={creds.access_key}')
      print(f'aws_secret_access_key={creds.secret_key}')
      print(f'aws_session_token={creds.token}')
      print(f'region={session.region_name}')
    else:
      # If the credentials are not temporary, generate temporary credentials
      sts = boto3.client('sts')
      temp_creds = sts.get_session_token()['Credentials']
      print(f'aws_access_key_id={creds.access_key}')
      print(f'aws_secret_access_key={creds.secret_key}')
      print(f'aws_session_token={creds.token}')
      print(f'region={session.region_name}')
  else:
    session = create_session(profile)
    client = session.client('sts')
    response = client.assume_role(
        RoleArn=role_arn,
        RoleSessionName='Assumed'
    )
    print(f'aws_access_key_id={response["Credentials"]["AccessKeyId"]}')
    print(f'aws_secret_access_key={response["Credentials"]["SecretAccessKey"]}')
    print(f'aws_session_token={response["Credentials"]["SessionToken"]}')
    print(f'region={session.region_name}')

if __name__ == '__main__':
  cli()
