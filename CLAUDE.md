# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

IFL-tools is a Python package providing convenient command-line tools for AWS infrastructure management. The tools are designed for listing, inspecting, and managing various AWS resources with a focus on simplicity and tabular output.

## Installation and Setup

Install the package using:
```bash
pip install -U git+https://github.com/utas-zyan/ifl-tools
```

## Core Architecture

### Tool Structure
- **Entry Points**: Each tool is defined as a Python script in `src/` with corresponding entry points in `pyproject.toml`
- **CLI Framework**: All tools use Click for command-line interface with consistent patterns
- **AWS Integration**: Built on boto3 with session management and profile support
- **Output Formatting**: Consistent table output using prettytable and tabulate libraries

### Main Components

1. **Resource Listing Tools** (`all.py`): 
   - Central command with subcommands for different AWS resources
   - Weight-based field filtering (0-9 scale)
   - JSON and table output modes
   - Supports: EC2, RDS, KMS, Secrets Manager, Route53, ALB, IAM roles, ACM certificates, AMIs, SSM parameters, subnets, ASGs

2. **Credential Management** (`cred_tool.py`):
   - AWS console login URL generation
   - Credential export in multiple formats
   - Profile and role assumption support

3. **Network Analysis** (`describe_network_resources.py`):
   - Cross-service network resource mapping
   - Security group rule analysis with caching
   - Subnet name resolution
   - Supports: EC2, RDS, ELB/ALBv2, Lambda, Redis/ElastiCache

4. **Utility Tools**:
   - `diff-secrets.py`: Compare Secrets Manager across profiles
   - `decrypt_auth_error.py`: Decode AWS authorization failure messages
   - `ssm` (bash): EC2 instance SSM session management with SSH key injection
   - `get_eks_config` (bash): EKS cluster kubeconfig setup

## Development Commands

### Building and Installation
```bash
# Install in development mode
pip install -e .

# Build package
python -m build
```

### Testing
```bash
# Run all tools (replace with actual instance/resource names)
all ec2
all rds
cred_tool login --profile myprofile
describe-network-resources --profile myprofile
```

## Key Patterns

### AWS Session Management
- Consistent session creation with optional profile support
- Credential handling for temporary and permanent credentials
- Debug mode via `DEBUG` environment variable

### Table Output
- Configurable field weights for detail levels
- Terminal width-aware formatting
- Consistent column alignment and truncation

### Caching
- TTL-based caching for expensive AWS API calls (20-minute default)
- Used extensively in network resource analysis

### Error Handling
- Graceful degradation for missing resources
- Debug output to stderr when `DEBUG=true`

## Common Usage Patterns

### Resource Discovery
```bash
# List all EC2 instances with high detail
all ec2 --weight 9

# Get minimal output
all ec2 --weight 0

# JSON output for scripting
all ec2 --json
```

### AWS Profile Management
```bash
# Generate console login URL
cred_tool login --profile production --role-arn arn:aws:iam::123456789:role/MyRole

# Export credentials for other tools
cred_tool export --profile production
```

### Instance Management
```bash
# Connect to instance via SSM
ssm my-instance-name

# Inject SSH key and connect
ssm my-instance-name ssh

# Run commands remotely
ssm my-instance-name run "ls -la"
```

## Configuration Files

- `pyproject.toml`: Package metadata, dependencies, and entry points
- `Makefile`: Contains AWS CLI commands for instance management
- `.gitignore`: Modified to exclude build artifacts and credentials

## Security Considerations

- Tools handle AWS credentials through boto3's standard credential chain
- No hardcoded credentials or sensitive information in code
- SSH key injection uses temporary files and proper cleanup
- Authorization error decoding requires appropriate STS permissions