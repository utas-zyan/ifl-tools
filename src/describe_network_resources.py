import boto3
import shutil
from tabulate import tabulate
from textwrap import fill, wrap
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

# Cache dictionaries with TTL
subnet_cache: Dict[str, Tuple[str, datetime]] = {}
security_group_cache: Dict[str, Tuple[List[str], datetime]] = {}
CACHE_TTL = timedelta(minutes=20)  # Cache results for 5 minutes

# Add at the top of the file with other globals
DEBUG_MODE = False  # Global debug toggle


def get_subnet_name(subnet_id: str) -> str:
  if subnet_id == 'N/A':
    return 'N/A'

  # Check cache first
  now = datetime.now()
  if subnet_id in subnet_cache:
    cached_value, cache_time = subnet_cache[subnet_id]
    if now - cache_time < CACHE_TTL:
      return cached_value

  # Cache miss - fetch from AWS
  ec2_client = boto3.client('ec2')
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


def get_security_group_info(security_group_ids: List[str]) -> str:
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
  ec2_client = boto3.client('ec2')
  security_groups = ec2_client.describe_security_groups(GroupIds=security_group_ids)

  sg_info = []
  for sg in security_groups['SecurityGroups']:
    # Format ingress rules
    ingress_rules = []
    for rule in sg.get('IpPermissions', []):
      for ip_range in rule.get('IpRanges', []):
        ingress_rules.append(
            f"({rule['IpProtocol']}:{rule.get('FromPort', 'N/A')}-{rule.get('ToPort', 'N/A')},{ip_range['CidrIp']})"
        )

    # Format egress rules
    egress_rules = []
    for rule in sg.get('IpPermissionsEgress', []):
      for ip_range in rule.get('IpRanges', []):
        egress_rules.append(
            f"({rule['IpProtocol']}:{rule.get('FromPort', 'N/A')}-{rule.get('ToPort', 'N/A')},{ip_range['CidrIp']})"
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


def get_ec2_info():
  ec2_client = boto3.client('ec2')
  instances = ec2_client.describe_instances()
  ec2_data = []
  for reservation in instances['Reservations']:
    for instance in reservation['Instances']:
      subnet_id = instance.get('SubnetId', 'N/A')
      if subnet_id == 'N/A':
        continue
      subnet_name = get_subnet_name(subnet_id)
      security_groups = get_security_group_info([sg['GroupId'] for sg in instance.get('SecurityGroups', [])])
      ec2_data.append({
          'Type': 'EC2',
          'Name': instance.get('InstanceId', 'N/A'),
          'SecurityGroups': security_groups,
          'Subnets': subnet_name
      })
      if DEBUG_MODE:
        return ec2_data  # Return after first instance in debug mode
  return ec2_data


def get_rds_info():
  rds_client = boto3.client('rds')
  instances = rds_client.describe_db_instances()
  rds_data = []
  for db_instance in instances['DBInstances']:
    subnet_name = db_instance.get('DBSubnetGroup', {}).get('DBSubnetGroupName', 'N/A')
    security_groups = get_security_group_info([sg['VpcSecurityGroupId'] for sg in db_instance.get('VpcSecurityGroups', [])])
    rds_data.append({
        'Type': 'RDS',
        'Name': db_instance.get('DBInstanceIdentifier', 'N/A'),
        'SecurityGroups': security_groups,
        'Subnets': subnet_name
    })
    if DEBUG_MODE:
      return rds_data  # Return after first instance in debug mode
  return rds_data


def get_elb_info():
  elb_client = boto3.client('elb')
  load_balancers = elb_client.describe_load_balancers()
  elb_data = []
  for lb in load_balancers['LoadBalancerDescriptions']:
    subnet_names = [get_subnet_name(subnet_id) for subnet_id in lb.get('Subnets', [])]
    security_groups = get_security_group_info(lb.get('SecurityGroups', []))
    elb_data.append({
        'Type': 'ELB',
        'Name': lb.get('LoadBalancerName', 'N/A'),
        'SecurityGroups': security_groups,
        'Subnets': ', '.join(subnet_names)
    })
    if DEBUG_MODE:
      return elb_data  # Return after first load balancer in debug mode
  return elb_data


def get_elbv2_info():
  elbv2_client = boto3.client('elbv2')
  load_balancers = elbv2_client.describe_load_balancers()
  elbv2_data = []
  for lb in load_balancers['LoadBalancers']:
    subnet_names = [get_subnet_name(subnet_id) for subnet_id in lb.get('Subnets', [])]
    security_groups = get_security_group_info(lb.get('SecurityGroups', []))
    elbv2_data.append({
        'Type': 'ELBv2',
        'Name': lb.get('LoadBalancerName', 'N/A'),
        'SecurityGroups': security_groups,
        'Subnets': ', '.join(subnet_names)
    })
    if DEBUG_MODE:
      return elbv2_data  # Return after first load balancer in debug mode
  return elbv2_data


def get_redis_info():
  elasticache_client = boto3.client('elasticache')
  clusters = elasticache_client.describe_cache_clusters(ShowCacheNodeInfo=True)
  redis_data = []
  for cluster in clusters['CacheClusters']:
    subnet_name = cluster.get('CacheSubnetGroupName', 'N/A')
    security_groups = get_security_group_info([sg['SecurityGroupId'] for sg in cluster.get('SecurityGroups', [])])
    redis_data.append({
        'Type': 'Redis',
        'Name': cluster.get('CacheClusterId', 'N/A'),
        'SecurityGroups': security_groups,
        'Subnets': subnet_name
    })
    if DEBUG_MODE:
      return redis_data  # Return after first cluster in debug mode
  return redis_data


def main(debug: bool = False):
  global DEBUG_MODE
  DEBUG_MODE = debug
  ec2_data = get_ec2_info()
  rds_data = get_rds_info()
  elb_data = get_elb_info()
  elbv2_data = get_elbv2_info()
  redis_data = get_redis_info()

  all_data = ec2_data + rds_data + elb_data + elbv2_data + redis_data

  # Get terminal width
  terminal_width = shutil.get_terminal_size().columns

  # Calculate max widths based on actual content
  type_width = max(len(str(item['Type'])) for item in all_data)
  name_width = max(len(str(item['Name'])) for item in all_data)
  subnet_width = max(len(str(item['Subnets'])) for item in all_data)

  # Add some padding
  type_width += 2
  name_width += 2
  subnet_width += 2

  # Security groups get the remaining space (minus margins and separators)
  margins_and_separators = 10  # Space for cell borders and padding
  sg_width = terminal_width - type_width - name_width - subnet_width - margins_and_separators
  last_line_lenth = 0
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
  main(debug=True)
