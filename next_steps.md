Prompt

Refer to the attached code.  Change or remove no functionality just add what we discuss.  output can be in sections i will re assemble if the output is too long.  Be clear on what to add and where to add it. 

regenerate the entire file as multipart and ill recombine - OMIT NOTHING start at the top and work to the end.


Done:
- IAM
- S3 Bucket sizes and object counts
- VPC
  - Route Table list
  - Routes
- DynamoDB
- Lambda Functions
- Bedrock

Combine Route Table list and Routes into 1 sheet

In Progress:

- Bedrock use?

To Do:

- break into smaller files - one file is becoming too large to find stuff easily
- run against specified regions only
- run against specified services only
- run against a specified aws profile from .aws directory
- Fix Security Groups with rules (put on one sheet)

- ECS Clusters and Services
- Elastic Load Balancers
- Auto Scaling Groups

Add formatting options:
Add color coding for statuses:
- Green for running/available
- Red for stopped/unavailable
- Yellow for transitioning states

Add more VPC-related resources:
- VPC Endpoints
- VPC Peering connections
- Transit Gateways


2. Add cost estimation:
- EC2 instance hourly costs
- RDS instance costs
- NAT Gateway hourly costs
- Data transfer estimates


3. Add filtering options:
# Examples:
python3 aws_resource_audit.py --tag-filter "Environment=Production"
python3 aws_resource_audit.py --vpc-id vpc-1234567
python3 aws_resource_audit.py --name-filter "*prod*"

4. Add export formats:
- CSV format
- HTML report
- PDF report

5. Add resource details:
- EC2 instance metrics (CPU, memory usage)
- RDS performance insights
- VPC Flow Logs info
- Resource tags
