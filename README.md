# aws-resource-auditor
Resource Auditor For AWS

I created this mostly to teach myself a few tricks.  So far im real happy with it and ill expand it as i go.

configure your aws account and run it.  As of now it will only check the default aws profile account - ill add a --profile option later.



# AWS Resource Auditor - Setup Instructions

## Prerequisites

1. Python 3.6 or higher
2. AWS credentials configured (`~/.aws/credentials` or environment variables)
3. Required Python packages:
```
boto3>=1.26.0
pandas>=1.3.0
xlsxwriter>=3.0.0
```

## Installation

1. Install required packages:
```bash
pip install boto3 pandas xlsxwriter
```

2. Save the script as `aws_auditor.py`
3. Make executable:
```bash
chmod +x aws_auditor.py
```

## Usage

### Basic Usage
```bash
python3 aws_auditor.py
```
This audits all services in all regions.

### Specific Regions
```bash
python3 aws_auditor.py --regions us-east-1,us-west-2
```

### Specific Services
```bash
python3 aws_auditor.py --services ec2,lambda,s3
```
Available services: ec2,rds,vpc,iam,s3,lambda

### Output
- Creates `results` directory in script location
- Generates two files:
  - Excel report: `aws_inventory_YYYYMMDD_HHMMSS.xlsx`
  - JSON data: `aws_inventory_YYYYMMDD_HHMMSS.json`

## AWS Permissions Required
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:Describe*",
                "rds:Describe*",
                "iam:List*",
                "iam:Get*",
                "s3:List*",
                "s3:GetBucket*",
                "lambda:List*",
                "lambda:Get*"
            ],
            "Resource": "*"
        }
    ]
}
```