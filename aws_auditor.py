#!/usr/bin/env python3
"""
AWS Resource Audit Tool
This script performs a comprehensive audit of AWS resources including:
- EC2 Instances and EIPs
- RDS Instances
- VPC Resources (VPCs, Subnets, IGWs, NAT Gateways)
- IAM Resources (Users, Roles, Groups)
- S3 Buckets
- Lambda Functions
- DynamoDB Tables
- Bedrock Models and Foundations

Usage:
  python3 aws_resource_audit.py
  python3 aws_resource_audit.py --regions us-east-1,us-west-2

Requirements:
  - boto3
  - pandas
  - xlsxwriter
"""

import boto3
import pandas as pd
import argparse
from datetime import datetime, timedelta
from botocore.exceptions import ClientError
import sys
import os
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

def check_aws_connection():
    try:
        session = boto3.Session()
        sts = session.client('sts')
        sts.get_caller_identity()
        print("Successfully connected to AWS")
        return True
    except Exception as e:
        print(f"AWS Connection Error: {e}")
        return False

def parse_arguments():
    parser = argparse.ArgumentParser(description='AWS Resource Audit Tool')
    parser.add_argument('--regions', type=str, 
                       help='Comma-separated list of regions (e.g., us-east-1,eu-west-1) or "all" for all regions',
                       default='all')
    parser.add_argument('--services', type=str, 
                       help='Comma-separated list of services (ec2,rds,vpc,iam,s3,lambda,dynamodb,bedrock)',
                       default='all')
    return parser.parse_args()

def write_dataframe(writer, sheet_name, data, header_format):
    """Helper function to write a DataFrame to Excel with formatting"""
    if data:
        df = pd.DataFrame(data)
        try:
            if 'Region' in df.columns and 'VPC ID' in df.columns:
                df.sort_values(['Region', 'VPC ID'], inplace=True)
            elif 'Region' in df.columns:
                df.sort_values('Region', inplace=True)
        except:
            pass
            
        df.to_excel(writer, sheet_name=sheet_name, index=False)
        worksheet = writer.sheets[sheet_name]
        for idx, col in enumerate(df.columns):
            worksheet.write(0, idx, col, header_format)
            worksheet.set_column(idx, idx, len(str(col)) + 2)
        print(f"  Added {len(data)} {sheet_name}")
        
def get_s3_metrics(s3, cloudwatch, bucket_name):
    """Get S3 bucket size and object count metrics using direct S3 API calls"""
    results = {
        'BucketSizeBytes': 'N/A',
        'NumberOfObjects': 'N/A'
    }
    
    try:
        total_size = 0
        total_objects = 0
        paginator = s3.get_paginator('list_objects_v2')
        
        for page in paginator.paginate(Bucket=bucket_name):
            if 'Contents' in page:
                for obj in page['Contents']:
                    total_size += obj.get('Size', 0)
                    total_objects += 1
        
        if total_size > 0:
            if total_size >= 1024**4:
                size_str = f"{total_size / (1024**4):.2f} TB"
            elif total_size >= 1024**3:
                size_str = f"{total_size / (1024**3):.2f} GB"
            elif total_size >= 1024**2:
                size_str = f"{total_size / (1024**2):.2f} MB"
            else:
                size_str = f"{total_size / 1024:.2f} KB"
            
            results['BucketSizeBytes'] = size_str
            results['NumberOfObjects'] = f"{total_objects:,}"
                
    except Exception as e:
        print(f"Error getting metrics for bucket {bucket_name}: {str(e)}")
    
    return results

def process_region(session, region):
    """Process a single region with error handling"""
    try:
        print(f"\nProcessing region: {region}")
        resources = get_resources(session, region)
        print(f"Successfully processed region: {region}")
        return resources
    except ClientError as e:
        if 'AuthorizationError' in str(e) or 'OptInRequired' in str(e):
            print(f"Region {region} is not enabled for this account. Skipping.")
            return None
        else:
            print(f"Error processing region {region}: {str(e)}")
            return None
    except Exception as e:
        print(f"Unexpected error processing region {region}: {str(e)}")
        return None

def audit_dynamodb(session, region):
    """Audit DynamoDB tables in a region"""
    print("  Checking DynamoDB tables...")
    dynamodb = session.client('dynamodb', region_name=region)
    dynamodb_resources = []

    try:
        paginator = dynamodb.get_paginator('list_tables')
        for page in paginator.paginate():
            for table_name in page['TableNames']:
                try:
                    table = dynamodb.describe_table(TableName=table_name)['Table']
                    tags_response = dynamodb.list_tags_of_resource(
                        ResourceArn=table['TableArn']
                    )
                    
                    try:
                        backup_status = dynamodb.describe_continuous_backups(
                            TableName=table_name
                        )['ContinuousBackupsDescription']['PointInTimeRecoveryDescription']['PointInTimeRecoveryStatus']
                    except:
                        backup_status = 'DISABLED'

                    dynamodb_resources.append({
                        'Region': region,
                        'Table Name': table['TableName'],
                        'ARN': table['TableArn'],
                        'Status': table['TableStatus'],
                        'Creation Time': str(table['CreationDateTime']),
                        'Item Count': table.get('ItemCount', 0),
                        'Size (Bytes)': table.get('TableSizeBytes', 0),
                        'Billing Mode': table.get('BillingModeSummary', {}).get('BillingMode', 'PROVISIONED'),
                        'Read Capacity': table.get('ProvisionedThroughput', {}).get('ReadCapacityUnits', 'N/A'),
                        'Write Capacity': table.get('ProvisionedThroughput', {}).get('WriteCapacityUnits', 'N/A'),
                        'Point-in-Time Recovery': backup_status,
                        'Stream Enabled': table.get('StreamSpecification', {}).get('StreamEnabled', False),
                        'Encryption Type': table.get('SSEDescription', {}).get('SSEType', 'N/A'),
                        'Global Table': bool(table.get('GlobalTableVersion', False)),
                        'Tags': ', '.join([f"{tag['Key']}={tag['Value']}" for tag in tags_response.get('Tags', [])])
                    })

                except ClientError as e:
                    print(f"Error processing table {table_name}: {str(e)}")
                    continue

    except ClientError as e:
        print(f"Error auditing DynamoDB in {region}: {str(e)}")

    return dynamodb_resources

def audit_bedrock(session, region):
    """Audit Bedrock resources in a region"""
    print("  Checking Bedrock resources...")
    bedrock = session.client('bedrock', region_name=region)
    bedrock_resources = []

    try:
        # List foundation models
        models = bedrock.list_foundation_models()
        for model in models['modelSummaries']:
            try:
                # Get detailed model info
                model_details = bedrock.get_foundation_model(
                    modelIdentifier=model['modelId']
                )

                bedrock_resources.append({
                    'Region': region,
                    'Model ID': model['modelId'],
                    'Model Name': model['modelName'],
                    'Provider': model['providerName'],
                    'Status': model.get('modelLifecycle', {}).get('status', 'N/A'),
                    'Input Modalities': ', '.join(model.get('inputModalities', [])),
                    'Output Modalities': ', '.join(model.get('outputModalities', [])),
                    'Custom Model': model.get('customizationsSupported', False),
                    'Fine Tuning Supported': model.get('customModelSupported', False),
                    'Response Streaming': model.get('responseStreamingSupported', False),
                    'Model ARN': model.get('modelArn', 'N/A'),
                    'Created At': str(model.get('createdAt', 'N/A')),
                    'Last Modified': str(model.get('lastModifiedAt', 'N/A'))
                })

            except ClientError as e:
                print(f"Error getting details for model {model['modelId']}: {str(e)}")
                continue

    except ClientError as e:
        print(f"Error auditing Bedrock in {region}: {str(e)}")

    return bedrock_resources

def get_resources(session, region):
    """Collect all AWS resources for a given region"""
    print(f"\nAuditing region: {region}")
    resources = {
        'ec2': [],
        'rds': [],
        'vpc': [],
        'lambda': [],
        'dynamodb': [],
        'bedrock': []
    }

    try:
        ec2 = session.client('ec2', region_name=region)
        print("  Checking EC2 instances...")
        
        try:
            eips = ec2.describe_addresses()['Addresses']
            eip_map = {eip.get('InstanceId'): eip for eip in eips if eip.get('InstanceId')}
        except ClientError as e:
            print(f"  Error accessing EIPs: {e}")
            eip_map = {}
            
        paginator = ec2.get_paginator('describe_instances')
        for page in paginator.paginate():
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    eip_info = eip_map.get(instance['InstanceId'], {})
                    tags = instance.get('Tags', [])
                    tag_dict = {tag['Key']: tag['Value'] for tag in tags}
                    
                    resources['ec2'].append({
                        'Region': region,
                        'Instance ID': instance['InstanceId'],
                        'Name': tag_dict.get('Name', 'N/A'),
                        'State': instance['State']['Name'],
                        'Instance Type': instance['InstanceType'],
                        'Platform': instance.get('Platform', 'linux'),
                        'Private IP': instance.get('PrivateIpAddress', 'N/A'),
                        'Public IP': instance.get('PublicIpAddress', 'N/A'),
                        'Elastic IP': eip_info.get('PublicIp', 'N/A'),
                        'EIP Allocation ID': eip_info.get('AllocationId', 'N/A'),
                        'VPC ID': instance.get('VpcId', 'N/A'),
                        'Subnet ID': instance.get('SubnetId', 'N/A'),
                        'Key Name': instance.get('KeyName', 'N/A'),
                        'Launch Time': str(instance.get('LaunchTime', 'N/A')),
                        'Security Groups': ', '.join([sg['GroupId'] for sg in instance.get('SecurityGroups', [])]),
                        'Environment': tag_dict.get('Environment', 'N/A'),
                        'Owner': tag_dict.get('Owner', 'N/A'),
                        'Cost Center': tag_dict.get('CostCenter', 'N/A')
                    })

        # RDS Resources
        print("  Checking RDS instances...")
        rds = session.client('rds', region_name=region)
        try:
            for db in rds.describe_db_instances()['DBInstances']:
                resources['rds'].append({
                    'Region': region,
                    'DB Identifier': db['DBInstanceIdentifier'],
                    'Status': db['DBInstanceStatus'],
                    'Engine': f"{db['Engine']} {db['EngineVersion']}",
                    'Instance Class': db['DBInstanceClass'],
                    'Storage': f"{db['AllocatedStorage']} GB",
                    'Storage Type': db['StorageType'],
                    'Multi-AZ': db.get('MultiAZ', False),
                    'Endpoint': db.get('Endpoint', {}).get('Address', 'N/A'),
                    'Port': db.get('Endpoint', {}).get('Port', 'N/A'),
                    'VPC ID': db.get('DBSubnetGroup', {}).get('VpcId', 'N/A'),
                    'Publicly Accessible': db.get('PubliclyAccessible', False)
                })
        except ClientError as e:
            print(f"  Error accessing RDS: {e}")

        # VPC Resources
        print("  Checking VPC resources...")
        try:
            vpcs = ec2.describe_vpcs()['Vpcs']
            for vpc in vpcs:
                vpc_id = vpc['VpcId']
                try:
                    print(f"    Processing VPC: {vpc_id}")
                    vpc_info = get_vpc_details(ec2, vpc_id, region)
                    if vpc_info:
                        resources['vpc'].append(vpc_info)
                        print(f"      Found {vpc_info.get('Route Tables', 0)} route tables")
                        print(f"      Found {vpc_info.get('Security Groups', 0)} security groups")
                        print(f"      Found {vpc_info.get('VPC Endpoints', 0)} endpoints")
                        print(f"      Found {vpc_info.get('Peering Connections', 0)} peering connections")
                        print(f"      Found {vpc_info.get('Transit Gateway Attachments', 0)} transit gateway attachments")
                except Exception as e:
                    print(f"    Error processing VPC {vpc_id}: {str(e)}")
                    continue
        except ClientError as e:
            print(f"  Error accessing VPCs: {str(e)}")

        # Lambda Resources
        resources['lambda'] = audit_lambda(session, region)
        
        # DynamoDB Resources
        resources['dynamodb'] = audit_dynamodb(session, region)

        # Bedrock Resources
        resources['bedrock'] = audit_bedrock(session, region)

    except ClientError as e:
        print(f"Error in region {region}: {str(e)}")
        
    print(f"\nResources found in {region}:")
    print(f"    EC2 instances: {len(resources['ec2'])}")
    print(f"    RDS instances: {len(resources['rds'])}")
    print(f"    VPC resources: {len(resources['vpc'])}")
    print(f"    Lambda functions: {len(resources['lambda'])}")
    print(f"    DynamoDB tables: {len(resources['dynamodb'])}")
    print(f"    Bedrock models: {len(resources['bedrock'])}")
    
    return resources

def get_route_table_details(ec2, vpc_id, region):
    route_tables = []
    try:
        paginator = ec2.get_paginator('describe_route_tables')
        for page in paginator.paginate(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]):
            for rt in page['RouteTables']:
                rt_info = {
                    'Region': region,
                    'VPC ID': vpc_id,
                    'Route Table ID': rt['RouteTableId'],
                    'Name': next((tag['Value'] for tag in rt.get('Tags', []) 
                                if tag['Key'] == 'Name'), 'N/A'),
                    'Main': any(assoc.get('Main', False) for assoc in rt.get('Associations', [])),
                    'Associated Subnets': ', '.join([assoc['SubnetId'] for assoc in rt.get('Associations', []) 
                                                   if 'SubnetId' in assoc])
                }
                routes = []
                for route in rt.get('Routes', []):
                    route_info = {
                        'Destination': route.get('DestinationCidrBlock', 
                                               route.get('DestinationIpv6CidrBlock', 'N/A')),
                        'Target': next((value for key, value in route.items() 
                                      if key.endswith('Id') or key.endswith('Gateway')), 'N/A'),
                        'Status': route.get('State', 'N/A'),
                        'Origin': route.get('Origin', 'N/A')
                    }
                    routes.append(route_info)
                rt_info['Routes'] = routes
                route_tables.append(rt_info)
    except ClientError as e:
        print(f"Error getting route table details for VPC {vpc_id}: {str(e)}")
    return route_tables

def get_security_group_details(ec2, vpc_id, region):
    security_groups = []
    try:
        paginator = ec2.get_paginator('describe_security_groups')
        for page in paginator.paginate(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]):
            for sg in page['SecurityGroups']:
                sg_info = {
                    'Region': region,
                    'VPC ID': vpc_id,
                    'Security Group ID': sg['GroupId'],
                    'Name': sg['GroupName'],
                    'Description': sg['Description']
                }
                inbound_rules = []
                for rule in sg.get('IpPermissions', []):
                    rule_info = {
                        'Protocol': rule.get('IpProtocol', 'N/A'),
                        'Port Range': f"{rule.get('FromPort', 'N/A')}-{rule.get('ToPort', 'N/A')}",
                        'Source': ', '.join([ip_range.get('CidrIp', 'N/A') 
                                           for ip_range in rule.get('IpRanges', [])] +
                                          [f"{group['GroupId']} ({group.get('GroupName', 'N/A')})" 
                                           for group in rule.get('UserIdGroupPairs', [])])
                    }
                    inbound_rules.append(rule_info)
                sg_info['Inbound Rules'] = inbound_rules
                
                outbound_rules = []
                for rule in sg.get('IpPermissionsEgress', []):
                    rule_info = {
                        'Protocol': rule.get('IpProtocol', 'N/A'),
                        'Port Range': f"{rule.get('FromPort', 'N/A')}-{rule.get('ToPort', 'N/A')}",
                        'Destination': ', '.join([ip_range.get('CidrIp', 'N/A') 
                                                for ip_range in rule.get('IpRanges', [])] +
                                               [f"{group['GroupId']} ({group.get('GroupName', 'N/A')})" 
                                                for group in rule.get('UserIdGroupPairs', [])])
                    }
                    outbound_rules.append(rule_info)
                sg_info['Outbound Rules'] = outbound_rules
                security_groups.append(sg_info)
    except ClientError as e:
        print(f"Error getting security group details for VPC {vpc_id}: {str(e)}")
    return security_groups

def get_vpc_endpoint_details(ec2, vpc_id, region):
    vpc_endpoints = []
    try:
        paginator = ec2.get_paginator('describe_vpc_endpoints')
        for page in paginator.paginate(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]):
            for endpoint in page['VpcEndpoints']:
                endpoint_info = {
                    'Region': region,
                    'VPC ID': vpc_id,
                    'Endpoint ID': endpoint['VpcEndpointId'],
                    'Service Name': endpoint['ServiceName'],
                    'Type': endpoint['VpcEndpointType'],
                    'State': endpoint['State'],
                    'Policy Status': endpoint.get('PolicyDocument', 'N/A'),
                    'Private DNS Enabled': endpoint.get('PrivateDnsEnabled', False),
                    'Subnets': ', '.join(endpoint.get('SubnetIds', [])),
                    'Security Groups': ', '.join(endpoint.get('Groups', [])),
                    'Network Interfaces': ', '.join(endpoint.get('NetworkInterfaceIds', []))
                }
                vpc_endpoints.append(endpoint_info)
    except ClientError as e:
        print(f"Error getting VPC endpoint details for VPC {vpc_id}: {str(e)}")
    return vpc_endpoints

def get_vpc_peering_details(ec2, vpc_id, region):
    peering_connections = []
    try:
        paginator = ec2.get_paginator('describe_vpc_peering_connections')
        filters = [{'Name': 'requester-vpc-info.vpc-id', 'Values': [vpc_id]}]
        for page in paginator.paginate(Filters=filters):
            for pcx in page['VpcPeeringConnections']:
                pcx_info = {
                    'Region': region,
                    'VPC ID': vpc_id,
                    'Peering Connection ID': pcx['VpcPeeringConnectionId'],
                    'Status': pcx['Status']['Code'],
                    'Requester VPC': pcx['RequesterVpcInfo']['VpcId'],
                    'Requester Region': pcx['RequesterVpcInfo']['Region'],
                    'Requester CIDR': pcx['RequesterVpcInfo'].get('CidrBlock', 'N/A'),
                    'Requester Owner': pcx['RequesterVpcInfo']['OwnerId'],
                    'Accepter VPC': pcx['AccepterVpcInfo']['VpcId'],
                    'Accepter Region': pcx['AccepterVpcInfo']['Region'],
                    'Accepter CIDR': pcx['AccepterVpcInfo'].get('CidrBlock', 'N/A'),
                    'Accepter Owner': pcx['AccepterVpcInfo']['OwnerId'],
                    'Cross Region': pcx['RequesterVpcInfo']['Region'] != pcx['AccepterVpcInfo']['Region'],
                    'DNS Resolution': pcx.get('RequesterVpcInfo', {}).get('PeeringOptions', {}).get('AllowDnsResolutionFromRemoteVpc', False)
                }
                peering_connections.append(pcx_info)
                
        # Check for peering connections where this VPC is the accepter
        filters = [{'Name': 'accepter-vpc-info.vpc-id', 'Values': [vpc_id]}]
        for page in paginator.paginate(Filters=filters):
            for pcx in page['VpcPeeringConnections']:
                pcx_info = {
                    'Region': region,
                    'VPC ID': vpc_id,
                    'Peering Connection ID': pcx['VpcPeeringConnectionId'],
                    'Status': pcx['Status']['Code'],
                    'Requester VPC': pcx['RequesterVpcInfo']['VpcId'],
                    'Requester Region': pcx['RequesterVpcInfo']['Region'],
                    'Requester CIDR': pcx['RequesterVpcInfo'].get('CidrBlock', 'N/A'),
                    'Requester Owner': pcx['RequesterVpcInfo']['OwnerId'],
                    'Accepter VPC': pcx['AccepterVpcInfo']['VpcId'],
                    'Accepter Region': pcx['AccepterVpcInfo']['Region'],
                    'Accepter CIDR': pcx['AccepterVpcInfo'].get('CidrBlock', 'N/A'),
                    'Accepter Owner': pcx['AccepterVpcInfo']['OwnerId'],
                    'Cross Region': pcx['RequesterVpcInfo']['Region'] != pcx['AccepterVpcInfo']['Region'],
                    'DNS Resolution': pcx.get('AccepterVpcInfo', {}).get('PeeringOptions', {}).get('AllowDnsResolutionFromRemoteVpc', False)
                }
                peering_connections.append(pcx_info)
    except ClientError as e:
        print(f"Error getting VPC peering details for VPC {vpc_id}: {str(e)}")
    return peering_connections

def get_transit_gateway_details(ec2, vpc_id, region):
    """Get detailed information about Transit Gateway attachments and routes"""
    tgw_resources = {
        'attachments': [],
        'route_tables': []
    }
    
    try:
        paginator = ec2.get_paginator('describe_transit_gateway_vpc_attachments')
        for page in paginator.paginate(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]):
            for attachment in page['TransitGatewayVpcAttachments']:
                attachment_info = {
                    'Region': region,
                    'VPC ID': vpc_id,
                    'Transit Gateway ID': attachment['TransitGatewayId'],
                    'Attachment ID': attachment['TransitGatewayAttachmentId'],
                    'State': attachment['State'],
                    'Subnets': ', '.join(attachment.get('SubnetIds', [])),
                    'Creation Time': str(attachment['CreationTime']),
                    'Tags': {tag['Key']: tag['Value'] for tag in attachment.get('Tags', [])}
                }
                tgw_resources['attachments'].append(attachment_info)
                
                try:
                    rt_response = ec2.describe_transit_gateway_route_tables(
                        Filters=[{'Name': 'transit-gateway-id', 'Values': [attachment['TransitGatewayId']]}]
                    )
                    
                    for rt in rt_response['TransitGatewayRouteTables']:
                        routes = []
                        try:
                            route_paginator = ec2.get_paginator('search_transit_gateway_routes')
                            for route_page in route_paginator.paginate(
                                TransitGatewayRouteTableId=rt['TransitGatewayRouteTableId'],
                                Filters=[{'Name': 'state', 'Values': ['active', 'blackhole']}]
                            ):
                                for route in route_page['Routes']:
                                    route_info = {
                                        'CIDR': route.get('DestinationCidrBlock', 'N/A'),
                                        'Type': route.get('Type', 'N/A'),
                                        'State': route.get('State', 'N/A'),
                                        'Attachment ID': next((match['TransitGatewayAttachmentId'] 
                                                            for match in route.get('TransitGatewayAttachments', [])), 'N/A')
                                    }
                                    routes.append(route_info)
                        except ClientError as e:
                            print(f"Error getting TGW routes: {str(e)}")
                            
                        rt_info = {
                            'Region': region,
                            'Transit Gateway ID': attachment['TransitGatewayId'],
                            'Route Table ID': rt['TransitGatewayRouteTableId'],
                            'State': rt['State'],
                            'Creation Time': str(rt['CreationTime']),
                            'Routes': routes
                        }
                        tgw_resources['route_tables'].append(rt_info)
                        
                except ClientError as e:
                    print(f"Error getting TGW route tables: {str(e)}")
                    
    except ClientError as e:
        print(f"Error getting Transit Gateway details for VPC {vpc_id}: {str(e)}")
    
    return tgw_resources

def audit_lambda(session, region):
    """Audit Lambda functions in a region"""
    print("  Checking Lambda functions...")
    lambda_client = session.client('lambda', region_name=region)
    lambda_resources = []

    try:
        paginator = lambda_client.get_paginator('list_functions')
        for page in paginator.paginate():
            for function in page['Functions']:
                try:
                    policy = lambda_client.get_policy(FunctionName=function['FunctionName'])
                    policy_json = json.loads(policy['Policy'])
                except ClientError:
                    policy_json = {}

                try:
                    tags = lambda_client.list_tags(Resource=function['FunctionArn'])['Tags']
                except ClientError:
                    tags = {}

                try:
                    concurrency = lambda_client.get_function_concurrency(
                        FunctionName=function['FunctionName']
                    ).get('ReservedConcurrentExecutions', 'Not configured')
                except ClientError:
                    concurrency = 'Error retrieving'

                lambda_resources.append({
                    'Region': region,
                    'Function Name': function['FunctionName'],
                    'ARN': function['FunctionArn'],
                    'Runtime': function['Runtime'],
                    'Handler': function['Handler'],
                    'Code Size': f"{function['CodeSize'] / (1024*1024):.2f} MB",
                    'Memory': f"{function['MemorySize']} MB",
                    'Timeout': f"{function['Timeout']} seconds",
                    'Last Modified': function['LastModified'],
                    'Environment Variables': len(function.get('Environment', {}).get('Variables', {})),
                    'Layers': len(function.get('Layers', [])),
                    'VPC Config': 'Yes' if function.get('VpcConfig', {}).get('VpcId') else 'No',
                    'VPC ID': function.get('VpcConfig', {}).get('VpcId', 'N/A'),
                    'Subnets': ', '.join(function.get('VpcConfig', {}).get('SubnetIds', [])),
                    'Security Groups': ', '.join(function.get('VpcConfig', {}).get('SecurityGroupIds', [])),
                    'Reserved Concurrency': concurrency,
                    'Architecture': function.get('Architectures', ['x86_64'])[0],
                    'Package Type': function.get('PackageType', 'Zip'),
                    'Resource Policy': bool(policy_json),
                    'Tags': ', '.join([f"{k}={v}" for k, v in tags.items()]) if tags else 'No Tags'
                })

    except ClientError as e:
        print(f"Error auditing Lambda functions in {region}: {str(e)}")

    return lambda_resources

def get_base_vpc_details(ec2, vpc_id, region):
    """Get basic VPC component information"""
    vpc_details = {
        'subnets': [],
        'internet_gateways': [],
        'nat_gateways': []
    }
    
    try:
        # Get subnet details
        subnets = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['Subnets']
        for subnet in subnets:
            vpc_details['subnets'].append({
                'Region': region,
                'VPC ID': vpc_id,
                'Subnet ID': subnet['SubnetId'],
                'Name': next((tag['Value'] for tag in subnet.get('Tags', []) 
                            if tag['Key'] == 'Name'), 'N/A'),
                'CIDR Block': subnet['CidrBlock'],
                'AZ': subnet['AvailabilityZone'],
                'Available IPs': subnet['AvailableIpAddressCount'],
                'Auto-assign Public IP': subnet.get('MapPublicIpOnLaunch', False),
                'State': subnet['State'],
                'Default': subnet.get('DefaultForAz', False)
            })

        # Get IGW details
        igws = ec2.describe_internet_gateways(
            Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}]
        )['InternetGateways']
        
        for igw in igws:
            vpc_details['internet_gateways'].append({
                'Region': region,
                'VPC ID': vpc_id,
                'IGW ID': igw['InternetGatewayId'],
                'Name': next((tag['Value'] for tag in igw.get('Tags', []) 
                            if tag['Key'] == 'Name'), 'N/A'),
                'State': next((attach['State'] for attach in igw['Attachments'] 
                             if attach['VpcId'] == vpc_id), 'N/A')
            })

        # Get NAT gateway details
        nat_gateways = ec2.describe_nat_gateways(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
        )['NatGateways']
        
        for ngw in nat_gateways:
            vpc_details['nat_gateways'].append({
                'Region': region,
                'VPC ID': vpc_id,
                'NAT Gateway ID': ngw['NatGatewayId'],
                'Name': next((tag['Value'] for tag in ngw.get('Tags', []) 
                            if tag['Key'] == 'Name'), 'N/A'),
                'Subnet ID': ngw['SubnetId'],
                'State': ngw['State'],
                'Public IP': next((addr['PublicIp'] for addr in ngw['NatGatewayAddresses']), 'N/A'),
                'Private IP': next((addr['PrivateIp'] for addr in ngw['NatGatewayAddresses']), 'N/A'),
                'Network Interface': next((addr['NetworkInterfaceId'] for addr in ngw['NatGatewayAddresses']), 'N/A'),
                'Created': str(ngw['CreateTime'])
            })

    except ClientError as e:
        print(f"Error getting VPC details for {vpc_id}: {str(e)}")

    return vpc_details

def get_vpc_details(ec2, vpc_id, region):
    """Get all VPC component information"""
    try:
        vpc = ec2.describe_vpcs(VpcIds=[vpc_id])['Vpcs'][0]
        base_details = get_base_vpc_details(ec2, vpc_id, region)
        route_tables = get_route_table_details(ec2, vpc_id, region)
        security_groups = get_security_group_details(ec2, vpc_id, region)
        endpoints = get_vpc_endpoint_details(ec2, vpc_id, region)
        peering = get_vpc_peering_details(ec2, vpc_id, region)
        transit = get_transit_gateway_details(ec2, vpc_id, region)

        vpc_info = {
            'Region': region,
            'VPC ID': vpc_id,
            'Name': next((tag['Value'] for tag in vpc.get('Tags', []) 
                        if tag['Key'] == 'Name'), 'N/A'),
            'CIDR Block': vpc['CidrBlock'],
            'State': vpc['State'],
            'Is Default': vpc.get('IsDefault', False),
            'DNS Hostnames Enabled': vpc.get('EnableDnsHostnames', False),
            'DNS Support Enabled': vpc.get('EnableDnsSupport', True),
            'subnets': base_details['subnets'],
            'internet_gateways': base_details['internet_gateways'],
            'nat_gateways': base_details['nat_gateways'],
            'route_tables': route_tables,
            'security_groups': security_groups,
            'vpc_endpoints': endpoints,
            'peering_connections': peering,
            'transit_gateway': transit,
            'Subnet Count': len(base_details['subnets']),
            'Internet Gateways': len(base_details['internet_gateways']),
            'NAT Gateways': len(base_details['nat_gateways']),
            'Route Tables': len(route_tables),
            'Security Groups': len(security_groups),
            'VPC Endpoints': len(endpoints),
            'Peering Connections': len(peering),
            'Transit Gateway Attachments': len(transit.get('attachments', [])),
            'Transit Gateway Route Tables': len(transit.get('route_tables', [])),
        }

        try:
            flow_logs = ec2.describe_flow_logs(
                Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
            )['FlowLogs']
            vpc_info['Flow Logs Enabled'] = len(flow_logs) > 0
        except:
            vpc_info['Flow Logs Enabled'] = False

        return vpc_info

    except ClientError as e:
        print(f"Error getting VPC details for {vpc_id}: {str(e)}")
        return {}
    
def audit_iam(session):
    """Audit IAM resources"""
    print("\nAuditing IAM resources...")
    iam = session.client('iam')
    iam_resources = {
        'users': [],
        'roles': [],
        'groups': []
    }

    try:
        # Get Users
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                access_keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
                mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']
                groups = iam.list_groups_for_user(UserName=user['UserName'])['Groups']
                attached_policies = iam.list_attached_user_policies(UserName=user['UserName'])['AttachedPolicies']
                inline_policies = iam.list_user_policies(UserName=user['UserName'])['PolicyNames']

                active_key_last_used = []
                for key in access_keys:
                    if key['Status'] == 'Active':
                        try:
                            key_last_used = iam.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                            last_used_date = key_last_used.get('AccessKeyLastUsed', {}).get('LastUsedDate', 'Never')
                            active_key_last_used.append(str(last_used_date))
                        except:
                            active_key_last_used.append('Error getting last used date')
                            
                iam_resources['users'].append({
                    'UserName': user['UserName'],
                    'UserId': user['UserId'],
                    'ARN': user['Arn'],
                    'Created': str(user['CreateDate']),
                    'PasswordLastUsed': str(user.get('PasswordLastUsed', 'Never')),
                    'AccessKeysActive': len([k for k in access_keys if k['Status'] == 'Active']),
                    'AccessKeysLastUsed': ', '.join(active_key_last_used) if active_key_last_used else 'N/A',
                    'MFAEnabled': len(mfa_devices) > 0,
                    'GroupMemberships': ', '.join([g['GroupName'] for g in groups]),
                    'AttachedPolicies': ', '.join([p['PolicyName'] for p in attached_policies]),
                    'InlinePolicies': len(inline_policies)
                })

        # Get Roles
        paginator = iam.get_paginator('list_roles')
        for page in paginator.paginate():
            for role in page['Roles']:
                attached_policies = iam.list_attached_role_policies(RoleName=role['RoleName'])['AttachedPolicies']
                inline_policies = iam.list_role_policies(RoleName=role['RoleName'])['PolicyNames']

                iam_resources['roles'].append({
                    'RoleName': role['RoleName'],
                    'RoleId': role['RoleId'],
                    'ARN': role['Arn'],
                    'Created': str(role['CreateDate']),
                    'Description': role.get('Description', 'N/A'),
                    'AttachedPolicies': ', '.join([p['PolicyName'] for p in attached_policies]),
                    'InlinePolicies': len(inline_policies),
                    'MaxSessionDuration': role.get('MaxSessionDuration', 3600),
                    'Path': role.get('Path', '/'),
                    'ServiceLinked': role.get('Path', '/').startswith('/aws-service-role/')
                })

        # Get Groups
        paginator = iam.get_paginator('list_groups')
        for page in paginator.paginate():
            for group in page['Groups']:
                attached_policies = iam.list_attached_group_policies(GroupName=group['GroupName'])['AttachedPolicies']
                inline_policies = iam.list_group_policies(GroupName=group['GroupName'])['PolicyNames']
                members = iam.get_group(GroupName=group['GroupName'])['Users']

                iam_resources['groups'].append({
                    'GroupName': group['GroupName'],
                    'GroupId': group['GroupId'],
                    'ARN': group['Arn'],
                    'Created': str(group['CreateDate']),
                    'MemberCount': len(members),
                    'Members': ', '.join([u['UserName'] for u in members]),
                    'AttachedPolicies': ', '.join([p['PolicyName'] for p in attached_policies]),
                    'InlinePolicies': len(inline_policies),
                    'Path': group.get('Path', '/')
                })

    except ClientError as e:
        print(f"Error auditing IAM: {str(e)}")

    return iam_resources

def audit_s3(session):
    """Audit S3 buckets"""
    print("\nAuditing S3 buckets...")
    s3 = session.client('s3')
    cloudwatch = session.client('cloudwatch')
    s3_resources = []

    try:
        buckets = s3.list_buckets()['Buckets']
        
        for bucket in buckets:
            try:
                location = s3.get_bucket_location(Bucket=bucket['Name'])
                region = location['LocationConstraint'] or 'us-east-1'
                
                try:
                    versioning = s3.get_bucket_versioning(Bucket=bucket['Name'])
                    versioning_status = versioning.get('Status', 'Disabled')
                except:
                    versioning_status = 'Unknown'
                
                try:
                    encryption = s3.get_bucket_encryption(Bucket=bucket['Name'])
                    encryption_enabled = True
                    encryption_type = encryption['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
                except:
                    encryption_enabled = False
                    encryption_type = 'None'
                
                try:
                    public_access = s3.get_public_access_block(Bucket=bucket['Name'])
                    public_access_blocked = all(public_access['PublicAccessBlockConfiguration'].values())
                except:
                    public_access_blocked = 'Unknown'
                    
                try:
                    policy_status = s3.get_bucket_policy_status(Bucket=bucket['Name'])
                    is_public = policy_status['PolicyStatus']['IsPublic']
                except:
                    is_public = 'Unknown'

                try:
                    lifecycle = s3.get_bucket_lifecycle_configuration(Bucket=bucket['Name'])
                    has_lifecycle_rules = len(lifecycle.get('Rules', [])) > 0
                except:
                    has_lifecycle_rules = False

                try:
                    tags = s3.get_bucket_tagging(Bucket=bucket['Name'])
                    tag_list = [f"{tag['Key']}={tag['Value']}" for tag in tags.get('TagSet', [])]
                except:
                    tag_list = []

                metrics = get_s3_metrics(s3, cloudwatch, bucket['Name'])

                s3_resources.append({
                    'BucketName': bucket['Name'],
                    'CreationDate': str(bucket['CreationDate']),
                    'Region': region,
                    'Size': metrics['BucketSizeBytes'],
                    'ObjectCount': metrics['NumberOfObjects'],
                    'Versioning': versioning_status,
                    'EncryptionEnabled': encryption_enabled,
                    'EncryptionType': encryption_type,
                    'PublicAccessBlocked': public_access_blocked,
                    'PublicPolicy': is_public,
                    'HasLifecycleRules': has_lifecycle_rules,
                    'Tags': ', '.join(tag_list) if tag_list else 'No Tags'
                })

            except ClientError as e:
                print(f"Error processing bucket {bucket['Name']}: {str(e)}")
                continue

    except ClientError as e:
        print(f"Error auditing S3: {str(e)}")

    return s3_resources

def write_vpc_sheets(writer, vpc_resources, header_format):
    """Write VPC resources to separate sheets in Excel"""
    vpc_main = []
    subnets_all = []
    igw_all = []
    nat_all = []
    combined_routes = []
    sg_all = []
    sg_rules_all = []
    endpoints_all = []
    peering_all = []
    tgw_attachments = []
    tgw_route_tables = []
    tgw_routes = []

    for vpc in vpc_resources:
        vpc_main.append({
            'Region': vpc['Region'],
            'VPC ID': vpc['VPC ID'],
            'Name': vpc['Name'],
            'CIDR Block': vpc['CIDR Block'],
            'State': vpc['State'],
            'Is Default': vpc['Is Default'],
            'Subnet Count': vpc['Subnet Count'],
            'Route Tables': vpc['Route Tables'],
            'Internet Gateways': vpc['Internet Gateways'],
            'NAT Gateways': vpc['NAT Gateways'],
            'DNS Hostnames Enabled': vpc['DNS Hostnames Enabled'],
            'DNS Support Enabled': vpc['DNS Support Enabled'],
            'Flow Logs Enabled': vpc['Flow Logs Enabled']
        })
        
# Continued from write_vpc_sheets function
        subnets_all.extend(vpc.get('subnets', []))
        igw_all.extend(vpc.get('internet_gateways', []))
        nat_all.extend(vpc.get('nat_gateways', []))
        
        for rt in vpc.get('route_tables', []):
            rt_base = {
                'Region': rt['Region'],
                'VPC ID': rt['VPC ID'],
                'Route Table ID': rt['Route Table ID'],
                'Name': rt['Name'],
                'Main': rt['Main'],
                'Associated Subnets': rt['Associated Subnets']
            }
            
            if not rt.get('Routes'):
                combined_routes.append(rt_base)
            else:
                for route in rt.get('Routes', []):
                    route_entry = rt_base.copy()
                    route_entry.update({
                        'Destination': route['Destination'],
                        'Target': route['Target'],
                        'Status': route['Status'],
                        'Origin': route['Origin']
                    })
                    combined_routes.append(route_entry)
        
        for sg in vpc.get('security_groups', []):
            sg_base = {k: v for k, v in sg.items() if k not in ['Inbound Rules', 'Outbound Rules']}
            sg_all.append(sg_base)
            
            for rule in sg.get('Inbound Rules', []):
                rule.update({
                    'Security Group ID': sg['Security Group ID'],
                    'VPC ID': sg['VPC ID'],
                    'Region': sg['Region'],
                    'Direction': 'Inbound'
                })
                sg_rules_all.append(rule)
            
            for rule in sg.get('Outbound Rules', []):
                rule.update({
                    'Security Group ID': sg['Security Group ID'],
                    'VPC ID': sg['VPC ID'],
                    'Region': sg['Region'],
                    'Direction': 'Outbound'
                })
                sg_rules_all.append(rule)
        
        endpoints_all.extend(vpc.get('vpc_endpoints', []))
        peering_all.extend(vpc.get('peering_connections', []))
        
        tgw = vpc.get('transit_gateway', {})
        tgw_attachments.extend(tgw.get('attachments', []))
        
        for rt in tgw.get('route_tables', []):
            rt_base = {k: v for k, v in rt.items() if k != 'Routes'}
            tgw_route_tables.append(rt_base)
            
            for route in rt.get('Routes', []):
                route['Route Table ID'] = rt['Route Table ID']
                route['Transit Gateway ID'] = rt['Transit Gateway ID']
                route['Region'] = rt['Region']
                tgw_routes.append(route)

    write_dataframe(writer, 'VPCs', vpc_main, header_format)
    write_dataframe(writer, 'Subnets', subnets_all, header_format)
    write_dataframe(writer, 'Internet Gateways', igw_all, header_format)
    write_dataframe(writer, 'NAT Gateways', nat_all, header_format)
    write_dataframe(writer, 'Routes', combined_routes, header_format)
    write_dataframe(writer, 'Security Groups', sg_all, header_format)
    write_dataframe(writer, 'Security Group Rules', sg_rules_all, header_format)
    write_dataframe(writer, 'VPC Endpoints', endpoints_all, header_format)
    write_dataframe(writer, 'VPC Peering', peering_all, header_format)
    write_dataframe(writer, 'Transit Gateway Attachments', tgw_attachments, header_format)
    write_dataframe(writer, 'Transit Gateway Route Tables', tgw_route_tables, header_format)
    write_dataframe(writer, 'Transit Gateway Routes', tgw_routes, header_format)
    
def write_iam_sheets(writer, iam_resources, header_format):
    write_dataframe(writer, 'IAM Users', iam_resources['users'], header_format)
    write_dataframe(writer, 'IAM Roles', iam_resources['roles'], header_format)
    write_dataframe(writer, 'IAM Groups', iam_resources['groups'], header_format)

def write_s3_sheet(writer, s3_resources, header_format):
    write_dataframe(writer, 'S3 Buckets', s3_resources, header_format)

def write_excel(all_results, output_path):
    """Generate Excel report with all resources"""
    print("\nGenerating Excel report...")
    
    with pd.ExcelWriter(output_path, engine='xlsxwriter') as writer:
        workbook = writer.book
        header_format = workbook.add_format({
            'bold': True,
            'bg_color': '#0066cc',
            'font_color': 'white',
            'border': 1
        })

        if 'iam' in all_results:
            write_iam_sheets(writer, all_results['iam'], header_format)
        
        if 's3' in all_results:
            write_s3_sheet(writer, all_results['s3'], header_format)
        
        # Process regional resources
        ec2_resources = []
        rds_resources = []
        vpc_resources = []
        lambda_resources = []
        dynamodb_resources = []
        bedrock_resources = []

        if 'regions' in all_results:
            for region, region_data in all_results['regions'].items():
                if isinstance(region_data.get('ec2'), list):
                    ec2_resources.extend(region_data['ec2'])
                if isinstance(region_data.get('rds'), list):
                    rds_resources.extend(region_data['rds'])
                if isinstance(region_data.get('vpc'), list):
                    vpc_resources.extend(region_data['vpc'])
                if isinstance(region_data.get('lambda'), list):
                    lambda_resources.extend(region_data['lambda'])
                if isinstance(region_data.get('dynamodb'), list):
                    dynamodb_resources.extend(region_data['dynamodb'])
                if isinstance(region_data.get('bedrock'), list):
                    bedrock_resources.extend(region_data['bedrock'])

        if ec2_resources:
            write_dataframe(writer, 'EC2 Instances', ec2_resources, header_format)
        if rds_resources:
            write_dataframe(writer, 'RDS Instances', rds_resources, header_format)
        if vpc_resources:
            write_vpc_sheets(writer, vpc_resources, header_format)
        if lambda_resources:
            write_dataframe(writer, 'Lambda Functions', lambda_resources, header_format)
        if dynamodb_resources:
            write_dataframe(writer, 'DynamoDB Tables', dynamodb_resources, header_format)
        if bedrock_resources:
            write_dataframe(writer, 'Bedrock Models', bedrock_resources, header_format)

        debug_info = [
            {'Category': 'Regions Found', 'Count': len(all_results.get('regions', {}))},
            {'Category': 'EC2 Instances', 'Count': len(ec2_resources)},
            {'Category': 'RDS Instances', 'Count': len(rds_resources)},
            {'Category': 'VPC Resources', 'Count': len(vpc_resources)},
            {'Category': 'Lambda Functions', 'Count': len(lambda_resources)},
            {'Category': 'DynamoDB Tables', 'Count': len(dynamodb_resources)},
            {'Category': 'Bedrock Models', 'Count': len(bedrock_resources)},
            {'Category': 'IAM Users', 'Count': len(all_results.get('iam', {}).get('users', []))},
            {'Category': 'IAM Roles', 'Count': len(all_results.get('iam', {}).get('roles', []))},
            {'Category': 'IAM Groups', 'Count': len(all_results.get('iam', {}).get('groups', []))},
            {'Category': 'S3 Buckets', 'Count': len(all_results.get('s3', []))}
        ]
        write_dataframe(writer, 'Resource Counts', debug_info, header_format)

        summary_info = [
            {'Category': 'Total Regions', 'Count': len(all_results.get('regions', {}))},
            {'Category': 'Successful Regions', 
             'Count': len([r for r in all_results['regions'].values() if 'error' not in r])},
            {'Category': 'Failed Regions', 
             'Count': len([r for r in all_results['regions'].values() if 'error' in r])}
        ]
        write_dataframe(writer, 'Region Summary', summary_info, header_format)
        
def main():
    args = parse_arguments()
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    results_dir = os.path.join(script_dir, 'results')
    os.makedirs(results_dir, exist_ok=True)

    session = boto3.Session()
    services = args.services.lower().split(',') if args.services != 'all' else ['ec2', 'rds', 'vpc', 'iam', 's3', 'lambda', 'dynamodb', 'bedrock']
    
    try:
        ec2 = session.client('ec2')
        available_regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
        
        if args.regions.lower() == 'all':
            regions = available_regions
        else:
            requested_regions = args.regions.split(',')
            invalid_regions = [r for r in requested_regions if r not in available_regions]
            if invalid_regions:
                print(f"Warning: Invalid regions specified: {', '.join(invalid_regions)}")
                print("Available regions:", ', '.join(available_regions))
                sys.exit(1)
            regions = requested_regions
            
        print(f"\nAuditing {len(regions)} regions: {', '.join(regions)}")
    except ClientError as e:
        print(f"Error getting regions: {str(e)}")
        return

    print(f"Starting AWS resource audit...")
    print(f"Services to audit: {', '.join(services)}")
    
    all_results = {
        'regions': {},
        'metadata': {
            'audit_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'services_audited': services,
            'regions_audited': regions
        }
    }

    if 'iam' in services:
        all_results['iam'] = audit_iam(session)

    if 's3' in services:
        all_results['s3'] = audit_s3(session)

    print_lock = Lock()
    total_regions = len(regions)
    processed_regions = 0

    with ThreadPoolExecutor(max_workers=min(10, len(regions))) as executor:
        future_to_region = {executor.submit(process_region, session, region): region 
                          for region in regions}
        
        for future in as_completed(future_to_region):
            region = future_to_region[future]
            try:
                result = future.result()
                with print_lock:
                    processed_regions += 1
                    print(f"\nProgress: {processed_regions}/{total_regions} regions processed")
                    
                if result is not None:
                    all_results['regions'][region] = result
                else:
                    all_results['regions'][region] = {'error': 'Region processing failed or region not enabled'}
                    
            except Exception as e:
                print(f"Error processing region {region}: {str(e)}")
                all_results['regions'][region] = {'error': str(e)}

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    json_path = os.path.join(results_dir, f'aws_inventory_{timestamp}.json')
    excel_path = os.path.join(results_dir, f'aws_inventory_{timestamp}.xlsx')

    try:
        with open(json_path, 'w') as f:
            json.dump(all_results, f, indent=2, default=str)
        print(f"\nJSON report saved to: {json_path}")
    except Exception as e:
        print(f"Error saving JSON report: {str(e)}")

    try:
        write_excel(all_results, excel_path)
        print(f"Excel report saved to: {excel_path}")
    except Exception as e:
        print(f"Error generating Excel report: {str(e)}")

    print("\nAudit complete!")

if __name__ == "__main__":
    if check_aws_connection():
        try:
            main()
        except Exception as e:
            print(f"Error in main execution: {e}")
            sys.exit(1)
            
