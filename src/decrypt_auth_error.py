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


def dprint(*args, **kwargs):
    if os.environ.get("DEBUG") and os.environ["DEBUG"].lower() != "false":
        pprint(*args, stream=sys.stderr, **kwargs)


def extract_encoded_message(error_message):
    try:
        start = error_message.index("Encoded authorization failure message: ") + len("Encoded authorization failure message: ")
        end = error_message.index(" status code:", start) if " status code:" in error_message else len(error_message)
        return error_message[start:end].strip()
    except ValueError:
        return None


def decode_auth_message(encoded_message):
    try:
        sts = boto3.client('sts')
        response = sts.decode_authorization_message(
            EncodedMessage=encoded_message
        )
        return json.dumps(json.loads(response['DecodedMessage']), indent=2)
    except Exception as e:
        return f"Error decoding message: {str(e)}"


@click.command()
@click.argument('message', required=False)
def main(message):
    """Decode AWS authorization failure messages. 
    Reads from stdin if no message is provided."""
    
    if not message:
        message = sys.stdin.read()

    encoded_message = extract_encoded_message(message)
    if not encoded_message:
        print("No encoded authorization message found in input", file=sys.stderr)
        sys.exit(1)

    decoded = decode_auth_message(encoded_message)
    print(decoded)


if __name__ == '__main__':
    main()
