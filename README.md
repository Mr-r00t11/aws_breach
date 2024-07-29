# AWS Exploit Tool

## Description

aws_breach is an auditing and exploitation tool for AWS. This tool allows you to enumerate IAM users, IAM roles, and S3 buckets, verify permissions, assume roles, and more. It is designed to help security professionals assess the security configuration of their AWS accounts.

## Features

- Enumerate IAM users
- Enumerate IAM roles
- Enumerate S3 buckets
- Assume roles with appropriate permissions
- Verify permissions for specific actions
- Authenticate across multiple regions if a region is not specified

## Requirements

- Python 3.6+
- `boto3`
- `colorama`

## Installation

1. Clone the repository:
  
```bash
git clone https://github.com/Mr-r00t11/aws_breach.git

cd aws_breach
```

2. Install the dependencies:

	`pip install boto3 colorama`
## Usage

### Parameters

- `--access_key`: AWS Access Key (required)
- `--secret_key`: AWS Secret Key (required)
- `--region`: AWS Region (optional, will attempt to authenticate across multiple regions if not specified)

![[Screenshot_1.png]](https://raw.githubusercontent.com/Mr-r00t11/aws_breach/main/img/Screenshot_1.png)
### Examples

#### Authenticate in a specific region

`python aws_exploit.py --access_key YOUR_ACCESS_KEY --secret_key YOUR_SECRET_KEY --region YOUR_REGION`

#### Authenticate across multiple regions

`python aws_exploit.py --access_key YOUR_ACCESS_KEY --secret_key YOUR_SECRET_KEY`

## Main Functions

### whoami

Prints the current identity of the authenticated user.

### list_iam_users

Enumerates all IAM users in the account.

### list_iam_roles

Enumerates all IAM roles in the account.

### list_s3_buckets

Enumerates all S3 buckets in the account.

### assume_role

Assumes a specific role given its ARN and a session name.

### check_permissions

Verifies the permissions of the authenticated user for a list of specific actions.

## Example Output

![[Screenshot_2.png]](https://raw.githubusercontent.com/Mr-r00t11/aws_breach/main/img/Screenshot_2.png)
