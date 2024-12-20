import sys
import boto3
import shutil
import json
from tabulate import tabulate
from textwrap import fill, wrap
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Union
import click
# Cache dictionaries with TTL
subnet_cache: Dict[str, Tuple[str, datetime]] = {}
security_group_cache: Dict[str, Tuple[List[str], datetime]] = {}
CACHE_TTL = timedelta(minutes=20)  # Cache results for 5 minutes


def get_boto3_client(service: str, profile: Optional[str] = None) -> boto3.client:
  """Create a boto3 client with optional profile"""
  if profile:
    session = boto3.Session(profile_name=profile)
    return session.client(service)
  return boto3.client(service)


def get_subnet_name(subnet_id: str, profile: Optional[str] = None) -> str:
  if subnet_id == 'N/A':
    return 'N/A'

  # Check cache first
  now = datetime.now()
  if subnet_id in subnet_cache:
    cached_value, cache_time = subnet_cache[subnet_id]
    if now - cache_time < CACHE_TTL:
      return cached_value

  # Cache miss - fetch from AWS
  ec2_client = get_boto3_client('ec2', profile)
  subnets = ec2_client.describe_subnets(SubnetIds=[subnet_id])
  # Look for the Name tag, fallback to subnet ID if not found
  for tag in subnets['Subnets'][0].get('Tags', []):
    if tag['Key'] == 'Name':
      result = tag['Value']
      break
  else:
    result = subnet_id

  # Update cache
  subnet_cache[subnet_id] = (result, now)
  return result


def get_security_group_info(security_group_ids: List[str], profile: Optional[str] = None) -> str:
    # Check cache first
    now = datetime.now()
    cache_hit = True
    cached_results = []

    for sg_id in security_group_ids:
        if sg_id in security_group_cache:
            cached_value, cache_time = security_group_cache[sg_id]
            if now - cache_time < CACHE_TTL:
                cached_results.extend(cached_value)
            else:
                cache_hit = False
                break
        else:
            cache_hit = False
            break

    if cache_hit:
        return '; '.join(cached_results)

    # Cache miss - fetch from AWS
    ec2_client = get_boto3_client('ec2', profile)
    security_groups = ec2_client.describe_security_groups(GroupIds=security_group_ids)

    sg_info = []
    for sg in security_groups['SecurityGroups']:
        # Format ingress rules
        ingress_rules = []
        for rule in sg.get('IpPermissions', []):
            sources = []
            for ip_range in rule.get('IpRanges', []):
                sources.append(ip_range['CidrIp'])
            for user_id_group_pair in rule.get('UserIdGroupPairs', []):
                sources.append(f"SG:{user_id_group_pair['GroupId']}")
            for prefix_list in rule.get('PrefixListIds', []):
                sources.append(f"PL:{prefix_list['PrefixListId']}")
            if not sources:
                sources.append("unknown source")
            ingress_rules.append(
                f"({rule['IpProtocol']}:{rule.get('FromPort', 'N/A')}-{rule.get('ToPort', 'N/A')},{','.join(sources)})"
            )

        # Format egress rules
        egress_rules = []
        for rule in sg.get('IpPermissionsEgress', []):
            destinations = []
            for ip_range in rule.get('IpRanges', []):
                destinations.append(ip_range['CidrIp'])
            for user_id_group_pair in rule.get('UserIdGroupPairs', []):
                destinations.append(f"SG:{user_id_group_pair['GroupId']}")
            for prefix_list in rule.get('PrefixListIds', []):
                destinations.append(f"PL:{prefix_list['PrefixListId']}")
            if not destinations:
                destinations.append("unknown destination")
            egress_rules.append(
                f"({rule['IpProtocol']}:{rule.get('FromPort', 'N/A')}-{rule.get('ToPort', 'N/A')},{','.join(destinations)})"
            )

        # Handle empty rules case
        if not ingress_rules:
            ingress_rules = ["(no inbound rules)"]
        if not egress_rules:
            egress_rules = ["(no outbound rules)"]

        # Format with proper spacing and line breaks
        info = (
            f"{sg['GroupName']}"
            f"[Ingress:({','.join(ingress_rules)}), "
            f"Egress:({','.join(egress_rules)})]"
        )
        sg_info.append(info)

        # Update cache for individual security group
        security_group_cache[sg['GroupId']] = ([info], now)

    return ';'.join(sg_info)


def get_ec2_info(profile: Optional[str] = None, region: Optional[str] = None, minimal: bool = False):
  ec2_client = get_boto3_client('ec2', profile)
  instances = ec2_client.describe_instances()
  ec2_data = []
  for reservation in instances['Reservations']:
    for instance in reservation['Instances']:
      subnet_id = instance.get('SubnetId', 'N/A')
      if subnet_id == 'N/A':
        continue

      # Get instance name from tags
      instance_name = 'unnamed'
      instance_id = instance.get('InstanceId', 'N/A')
      for tag in instance.get('Tags', []):
        if tag['Key'] == 'Name':
          instance_name = tag['Value']
          break

      # Format as "name (id)"
      instance_identifier = f"{instance_name} ({instance_id})"

      subnet_name = get_subnet_name(subnet_id, profile)
      security_groups = get_security_group_info([sg['GroupId'] for sg in instance.get('SecurityGroups', [])], profile)
      ec2_data.append({
          'Type': 'EC2',
          'Name': instance_identifier,
          'SecurityGroups': security_groups,
          'Subnets': subnet_name
      })
      if minimal:
        return ec2_data  # Return after first instance in minimal mode
  return ec2_data


def get_rds_info(profile: Optional[str] = None, region: Optional[str] = None, minimal: bool = False):
  rds_client = get_boto3_client('rds', profile)
  instances = rds_client.describe_db_instances()
  rds_data = []
  for db_instance in instances['DBInstances']:
    # Get subnet names from the DB subnet group
    subnet_names = []
    if 'DBSubnetGroup' in db_instance:
      subnet_group = db_instance['DBSubnetGroup']
      # Get all subnets in the DB subnet group
      for subnet in subnet_group.get('Subnets', []):
        subnet_id = subnet.get('SubnetIdentifier')
        if subnet_id:
          subnet_name = get_subnet_name(subnet_id, profile)
          subnet_names.append(subnet_name)

    security_groups = get_security_group_info([sg['VpcSecurityGroupId'] for sg in db_instance.get('VpcSecurityGroups', [])], profile)
    rds_data.append({
        'Type': 'RDS',
        'Name': db_instance.get('DBInstanceIdentifier', 'N/A'),
        'SecurityGroups': security_groups,
        'Subnets': ', '.join(subnet_names) if subnet_names else 'N/A'
    })
    if minimal:
      return rds_data  # Return after first instance in minimal mode
  return rds_data


def get_elb_info(profile: Optional[str] = None, region: Optional[str] = None, minimal: bool = False):
  elb_client = get_boto3_client('elb', profile)
  load_balancers = elb_client.describe_load_balancers()
  elb_data = []
  for lb in load_balancers['LoadBalancerDescriptions']:
    # Get subnet names for all configured subnets
    subnet_names = []
    for az in lb.get('AvailabilityZones', []):
      subnet_id = az['SubnetId']
      subnet_name = get_subnet_name(subnet_id, profile)
      subnet_names.append(subnet_name)

    security_groups = get_security_group_info(lb.get('SecurityGroups', []), profile)
    elb_data.append({
        'Type': 'ELB',
        'Name': lb.get('LoadBalancerName', 'N/A'),
        'SecurityGroups': security_groups,
        'Subnets': ', '.join(subnet_names) if subnet_names else 'N/A'
    })
    if minimal:
      return elb_data  # Return after first load balancer in minimal mode
  return elb_data


def get_elbv2_info(profile: Optional[str] = None, region: Optional[str] = None, minimal: bool = False):
  elbv2_client = get_boto3_client('elbv2', profile)
  load_balancers = elbv2_client.describe_load_balancers()
  elbv2_data = []
  for lb in load_balancers['LoadBalancers']:
    # Get subnet names for all configured subnets
    subnet_names = []
    for az in lb.get('AvailabilityZones', []):
      subnet_id = az['SubnetId']
      subnet_name = get_subnet_name(subnet_id, profile)
      subnet_names.append(subnet_name)

    security_groups = get_security_group_info(lb.get('SecurityGroups', []), profile)
    elbv2_data.append({
        'Type': f"ELBv2 ({lb.get('Type', 'unknown')})",  # Show ALB/NLB/GWLB type
        'Name': lb.get('LoadBalancerName', 'N/A'),
        'SecurityGroups': security_groups,
        'Subnets': ', '.join(subnet_names) if subnet_names else 'N/A'
    })
    if minimal:
      return elbv2_data  # Return after first load balancer in minimal mode
  return elbv2_data


def get_redis_info(profile: Optional[str] = None, region: Optional[str] = None, minimal: bool = False):
  elasticache_client = get_boto3_client('elasticache', profile)
  clusters = elasticache_client.describe_cache_clusters(ShowCacheNodeInfo=True)
  redis_data = []
  for cluster in clusters['CacheClusters']:
    # Get subnet names from the cache subnet group
    subnet_names = []
    if 'CacheSubnetGroupName' in cluster:
      # Get the subnet group details
      subnet_group = elasticache_client.describe_cache_subnet_groups(
          CacheSubnetGroupName=cluster['CacheSubnetGroupName']
      )['CacheSubnetGroups'][0]
      
      # Get all subnets in the cache subnet group
      for subnet in subnet_group.get('Subnets', []):
        subnet_id = subnet.get('SubnetIdentifier')
        if subnet_id:
          subnet_name = get_subnet_name(subnet_id, profile)
          subnet_names.append(subnet_name)

    security_groups = get_security_group_info(
        [sg['SecurityGroupId'] for sg in cluster.get('SecurityGroups', [])],
        profile
    )
    
    redis_data.append({
        'Type': 'Redis',
        'Name': cluster.get('CacheClusterId', 'N/A'),
        'SecurityGroups': security_groups,
        'Subnets': ', '.join(subnet_names) if subnet_names else 'N/A'
    })
    if minimal:
      return redis_data  # Return after first cluster in minimal mode
  return redis_data


def get_lambda_info(profile: Optional[str] = None, region: Optional[str] = None, minimal: bool = False):
    lambda_client = get_boto3_client('lambda', profile)
    functions = lambda_client.list_functions()
    lambda_data = []
    
    for func in functions['Functions']:
        vpc_config = func.get('VpcConfig', {})
        if not vpc_config:
            continue  # Skip Lambda functions not in a VPC
            
        subnet_ids = vpc_config.get('SubnetIds', [])
        security_group_ids = vpc_config.get('SecurityGroupIds', [])
        
        # Get subnet names
        subnet_names = []
        for subnet_id in subnet_ids:
            subnet_name = get_subnet_name(subnet_id, profile)
            subnet_names.append(subnet_name)
            
        security_groups = get_security_group_info(security_group_ids, profile)
        
        lambda_data.append({
            'Type': 'Lambda',
            'Name': func.get('FunctionName', 'N/A'),
            'SecurityGroups': security_groups,
            'Subnets': ', '.join(subnet_names) if subnet_names else 'N/A'
        })
        
        if minimal:
            return lambda_data  # Return after first function in minimal mode
            
    return lambda_data


@click.command(help='List network resources and show their seucurity groups.')
@click.option('--profile', '-P', help='Which profile to use. If not specified, then use current one', default=None)
@click.option('--region', '-R', help='Which region to use. If not specified, then use current one', default=None)
@click.option('--minimal', "-M", type=bool, help='Minimal (only run with print one resource with one resource type)', default=False)
def main(profile: str = None, region: str = None, minimal: bool = False):
  # Pass minimal parameter to each info gathering function
  ec2_data = get_ec2_info(profile, region, minimal)
  rds_data = get_rds_info(profile, region, minimal)
  elb_data = get_elb_info(profile, region, minimal)
  elbv2_data = get_elbv2_info(profile, region, minimal)
  redis_data = get_redis_info(profile, region, minimal)
  lambda_data = get_lambda_info(profile, region, minimal)

  all_data = ec2_data + rds_data + elb_data + elbv2_data + redis_data + lambda_data

  # Get terminal width
  if sys.stdout.isatty() :
    terminal_width = shutil.get_terminal_size().columns
  else:
    terminal_width = 240

  # Calculate max widths based on actual content
  type_width = max(len(str(item['Type'])) for item in all_data)
  name_width = max(len(str(item['Name'])) for item in all_data)
  subnet_width = max(len(str(item['Subnets'])) for item in all_data)
  if subnet_width > 29:
    subnet_width = 29

  # Add some padding
  type_width += 2
  name_width += 2
  subnet_width += 2

  # Security groups get the remaining space (minus margins and separators)
  margins_and_separators = 10  # Space for cell borders and padding
  sg_width = terminal_width - type_width - name_width - subnet_width - margins_and_separators

  # Format security groups info for better readability
  for item in all_data:
    if 'SecurityGroups' in item:
      sg_info = item['SecurityGroups'].split(';')
      formatted_sgs = []

      for sg in sg_info:
        if '[' in sg:
          name, rules = sg.split('[', 1)
          rules = rules.rstrip(']')

          # Calculate available width for rules
          name_indent = 2
          rule_indent = 4
          available_width = sg_width - rule_indent

          # Format rules with proper indentation
          lines = []
          lines.append(f"{name.strip()} [".ljust(sg_width , ' '))

          # Split and format ingress/egress rules
          parts = rules.split('Egress:')
          ingress = parts[0].replace('Ingress:', '').strip()
          egress = parts[1].strip() if len(parts) > 1 else ""

          # Format ingress rules
          lines.append(f"{'>' * name_indent}Ingress:{ingress}".ljust(sg_width , ' '))

          # Format egress rules if present
          if egress:
            lines.append(f"{'>' * name_indent}Egress:{egress}".ljust(sg_width , ' '))

          lines.append("]".ljust(sg_width , ' '))
          formatted_sgs.append(''.join(lines).ljust(sg_width , ' '))
        else:
          formatted_sgs.append(sg.ljust(sg_width , ' '))

      item['SecurityGroups'] = ''.join(formatted_sgs)

  # Print with calculated column widths
  print(tabulate(
      all_data,
      headers="keys",
      tablefmt="grid",
      maxcolwidths=[type_width, name_width, sg_width, subnet_width],
      numalign="left",
      stralign="left"
  ))


if __name__ == "__main__":
  main()
