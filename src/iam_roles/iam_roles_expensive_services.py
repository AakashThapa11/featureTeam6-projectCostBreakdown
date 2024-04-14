import json
import logging
import boto3
import pandas as pd
from io import BytesIO
import os
import gzip
import io
from prometheus_client import CollectorRegistry, Gauge, push_to_gateway

try:
    ec2_client = boto3.client('ec2', region_name='ap-southeast-2')
except Exception as e:
    logging.error("Error creating boto3 client: " + str(e))

try:
    iam_client = boto3.client("iam")
except Exception as e:
    logging.error("Error creating boto3 client: " + str(e))

try:
    lambda_client = boto3.client("lambda")
except Exception as e:
    logging.error("Error creating boto3 client: " + str(e))

try:
    s3 = boto3.client("s3")
except Exception as e:
    logging.error("Error creating boto3 client: " + str(e))

cur_bucket_name = os.environ["bucket_name_get_report"]
report_prefix = os.environ["report_prefix"]
resource_cost_breakdown_lambda = os.environ["lambda_function_name"]

def get_iam_role_region(role_name):
    try:
        response = iam_client.get_role(RoleName=role_name)
        role_last_used = response.get('Role', {}).get('RoleLastUsed', {})
        if role_last_used and 'Region' in role_last_used:
            return role_last_used['Region']
        return "global"
    except Exception as e:
        print(f"Error occurred while getting IAM role '{role_name}': {str(e)}")
        return None

def get_latest_cost_and_usage_report(cur_bucket_name, report_prefix):
    s3 = boto3.client('s3')
    response = s3.list_objects_v2(Bucket=cur_bucket_name, Prefix=report_prefix)
    report_keys = [(obj["Key"], obj["LastModified"]) for obj in response.get("Contents", [])]
    sorted_report_keys = sorted(report_keys, key=lambda x: x[1], reverse=False)
    if sorted_report_keys:
        latest_report_key = sorted_report_keys[0][0]
        return latest_report_key
    else:
        print("No Cost and Usage Reports found.")
        return None

def read_content_of_report(cur_bucket_name, report_prefix):
    latest_report_key = get_latest_cost_and_usage_report(cur_bucket_name, report_prefix)
    response = s3.get_object(Bucket=cur_bucket_name, Key=latest_report_key)
    gzip_content = response['Body'].read()
    with gzip.GzipFile(fileobj=io.BytesIO(gzip_content), mode='rb') as f:
        report_data = f.read().decode('utf-8')
    df = pd.read_csv(io.StringIO(report_data))
    return df
    
def combine_costs_by_resource(df):
    resource_costs = df.groupby('lineItem/ResourceId')['lineItem/UnblendedCost'].sum().reset_index()
    combined_df = pd.merge(resource_costs, df[['lineItem/ResourceId', 'lineItem/ProductCode']], on='lineItem/ResourceId', how='left')
    combined_df = combined_df.drop_duplicates(subset=['lineItem/ResourceId'])
    return combined_df

def get_lambda_functions_in_role(role_name, combined_costs_df):
    try:
        response = lambda_client.list_functions()
        functions = response['Functions']
        role_functions = []
        for function in functions:
            function_arn = function['FunctionArn']
            function_name = function['FunctionName']
            function_role = function['Role']
            function_region = function_arn.split(':')[3]
            resourceIdIndex = combined_costs_df[combined_costs_df["lineItem/ResourceId"] == function_arn].index
            if len(resourceIdIndex) > 0:
                lambda_cost = combined_costs_df.loc[resourceIdIndex[0], "lineItem/UnblendedCost"]
            else:
                lambda_cost = 0
            if function_role.endswith(role_name):
                role_functions.append({
                    "ResourceName": function_name,
                    "ResourceId": function_arn,
                    "ResourceRegion": function_region,
                    "InstanceCost": lambda_cost
                })
        return role_functions
    except Exception as e:
        logging.error(f"Error occurred while getting Lambda functions for IAM role '{role_name}': {str(e)}")
        return []

def get_cloudwatch_costs(lambda_function_name, combined_costs_df):
    cloudwatch_costs = []
    for index, row in combined_costs_df.iterrows():
        product_code = row.get('lineItem/ProductCode')
        if product_code == 'AmazonCloudWatch':
            resource_id = row.get('lineItem/ResourceId')
            parts = resource_id.split(':')
            if len(parts) >= 7:
                lambda_function_name_in_arn = parts[-1].split('/')[-1]
                resource_region = parts[3]
                if lambda_function_name == lambda_function_name_in_arn:
                    unblended_cost = row.get('lineItem/UnblendedCost')
                    cloudwatch_costs.append({'ResourceId': resource_id, 'InstanceCost': unblended_cost, 'ResourceRegion': resource_region})
    return cloudwatch_costs
    
    
def get_sns_topic_for_lambda(lambda_function_arn, combined_costs_df):
    # Initialize the SNS client
    sns_client = boto3.client('sns')

    # List all SNS subscriptions
    subscriptions_response = sns_client.list_subscriptions()

    # Initialize a list to store the resource details
    resource_details = []

    # Iterate over each subscription
    for subscription in subscriptions_response['Subscriptions']:
        # Extract the subscription protocol and endpoint (Lambda function ARN)
        protocol = subscription['Protocol']
        endpoint = subscription['Endpoint']
        
        # Check if the subscription is for invoking the provided Lambda function
        if protocol == 'lambda' and endpoint == lambda_function_arn:
            # Extract the SNS topic ARN
            topic_arn = subscription['TopicArn']
            
            # Calculate the cost of the SNS topic from the combined costs dataframe
            sns_topic_cost = combined_costs_df.loc[combined_costs_df['lineItem/ResourceId'] == topic_arn, 'lineItem/UnblendedCost'].sum()
            
            # Add the resource details to the list
            resource_details.append({
                "ResourceName": topic_arn, 
                "ResourceId": topic_arn,
                "ResourceRegion": "Global",  
                "InstanceCost": sns_topic_cost
            })

    return resource_details



def get_sqs_mappings_for_lambda(lambda_function_arn, combined_costs_df):
    lambda_client = boto3.client('lambda')

    # List event source mappings for Lambda functions
    mappings_response = lambda_client.list_event_source_mappings()

    # Initialize a list to store the SQS mappings
    sqs_mappings = []

    for mapping in mappings_response['EventSourceMappings']:
        # Check if the mapping is for the given Lambda function
        if 'FunctionArn' in mapping and mapping['FunctionArn'] == lambda_function_arn:
            # Extract the SQS queue ARN
            if 'EventSourceArn' in mapping:
                sqs_queue_arn = mapping['EventSourceArn']
                
                # Extract region from SQS ARN
                parts = sqs_queue_arn.split(':')
                if len(parts) >= 4:
                    sqs_region = parts[3]
                
                # Get the SQS queue cost
                sqs_cost = combined_costs_df.loc[combined_costs_df['lineItem/ResourceId'] == sqs_queue_arn, 'lineItem/UnblendedCost'].sum()
                
                # Append SQS mapping details
                sqs_mappings.append({
                    "ResourceName": sqs_queue_arn,
                    "ResourceId": sqs_queue_arn,
                    "ResourceRegion": sqs_region,
                    "InstanceCost": sqs_cost
                })

    return sqs_mappings
    
    
def get_associated_eks_clusters(iam_role_name, combined_costs_df):
    # Initialize the EKS client
    eks_client = boto3.client('eks')
    
    # Get the list of all EKS clusters
    clusters_response = eks_client.list_clusters()
    
    # Extract cluster names associated with the IAM role
    associated_clusters = []
    for cluster_name in clusters_response.get('clusters', []):
        # Describe the EKS cluster to get its IAM role ARN
        cluster_info = eks_client.describe_cluster(name=cluster_name)
        cluster_iam_role_arn = cluster_info.get('cluster', {}).get('roleArn', '')
        
        # Check if the IAM role ARN matches the given IAM role name
        if cluster_iam_role_arn and iam_role_name in cluster_iam_role_arn:
            eks_cluster_region = cluster_info.get('cluster', {}).get('region', '')
            eks_cluster_arn = cluster_info.get('cluster', {}).get('arn', '')
            eks_cluster_name = cluster_info.get('cluster', {}).get('name', '')
            
            # Get the cost for the EKS cluster from the combined costs dataframe
            eks_cluster_cost = combined_costs_df.loc[combined_costs_df['lineItem/ResourceId'] == eks_cluster_arn, 'lineItem/UnblendedCost'].sum()
            
            associated_clusters.append({
                "ResourceName": eks_cluster_name,
                "ResourceId": eks_cluster_arn,
                "ResourceRegion": eks_cluster_region,
                "InstanceCost": eks_cluster_cost
            })
    
    return associated_clusters


def get_ecs_clusters(iam_role_name, combined_costs_df):
    """
    Retrieve the list of ECS clusters in the current region along with their tasks, check if the task role matches the IAM role provided,
    and get the cost of each task from the combined costs DataFrame.

    Args:
    - iam_role_name (str): The name of the IAM role to match with the task roles.
    - combined_costs_df (pd.DataFrame): DataFrame containing cost data.

    Returns:
        A list of dictionaries containing information about each ECS cluster, its tasks, and the associated costs.
    """
    try:
        ecs_client = boto3.client('ecs')
        response = ecs_client.list_clusters()
        cluster_arns = response.get('clusterArns', [])
        clusters = []

        # Filter the combined costs DataFrame for ECS services
        ecs_costs_df = combined_costs_df[combined_costs_df['lineItem/ProductCode'] == 'AmazonECS']

        for cluster_arn in cluster_arns:
            cluster_name = cluster_arn.split('/')[-1]
            cluster_details = ecs_client.describe_clusters(clusters=[cluster_arn])
            cluster_info = cluster_details.get('clusters', [])[0]

            # Retrieve tasks for the cluster
            tasks_response = ecs_client.list_tasks(cluster=cluster_arn)
            task_arns = tasks_response.get('taskArns', [])

            # Only include clusters with at least one task
            if task_arns:
                # Retrieve task details including task definition
                tasks_info = ecs_client.describe_tasks(cluster=cluster_arn, tasks=task_arns)

                # Extract task definitions and IAM roles associated with each task
                task_definitions = {}
                task_roles = {}
                for task in tasks_info['tasks']:
                    task_definition_arn = task['taskDefinitionArn']
                    task_role_arn = None

                    if task_definition_arn not in task_definitions:
                        task_definition_response = ecs_client.describe_task_definition(taskDefinition=task_definition_arn)
                        task_definition = task_definition_response['taskDefinition']
                        task_role_arn = task_definition['executionRoleArn']
                        task_definitions[task_definition_arn] = task_definition
                        task_roles[task_definition_arn] = task_role_arn
                    else:
                        task_role_arn = task_roles[task_definition_arn]

                    # Check if the task role ARN matches the IAM role provided
                    if task_role_arn == iam_role_name:
                        # Extract task ARN from the response
                        task_arn = task['taskArn']
                        parts = task_arn.split(':')
                        if len(parts) >= 4:
                            task_region = parts[3]

                        # Get the cost for the task from the combined costs DataFrame
                        task_cost_row = ecs_costs_df[ecs_costs_df['lineItem/ResourceId'] == task_arn]
                        task_cost = task_cost_row['lineItem/UnblendedCost'].values[0] if not task_cost_row.empty else 0

                        # Add cluster, task, role, and cost information to the list
                        cluster_data = {
                            "ResourceName": cluster_name,
                            "ResourceId": task_arn,
                            "ResourceRegion": task_region,
                            "InstanceCost": task_cost
                        }
                        clusters.append(cluster_data)

        return clusters
    except Exception as e:
        print(f"Error occurred while retrieving ECS clusters and tasks: {str(e)}")
        return []


def lambda_handler(event, context):
    try:
        response = iam_client.list_roles()
        resource_mapping = []
        df = read_content_of_report(cur_bucket_name, report_prefix)
        combined_costs_df = combine_costs_by_resource(df)
        
        for role_iterator in range(len(response['Roles'])):
            service_mapping = []
            role_arn = response['Roles'][role_iterator]["Arn"]
            role_name = response['Roles'][role_iterator]["RoleName"]
            role_region = get_iam_role_region(role_name)
            statement_service = response['Roles'][role_iterator]["AssumeRolePolicyDocument"]["Statement"]
            role_cost = 0
            
            for statement in statement_service:
                data_principal = statement.get("Principal", {})
                service = data_principal.get("Service", "")
                if isinstance(service, list):
                    service_list = [s.split(".")[0] for s in service]
                else:
                    service_list = [service.split(".")[0]] if service else []
                
                for resource in service_list:
                    if resource == "ec2":
                        if role_region == "None":
                            continue
                        else:
                            service_client = boto3.client(resource, region_name=role_region)
                        
                        try:
                            instance_profile_detail = iam_client.list_instance_profiles_for_role(RoleName=role_name)
                        except Exception as e:
                            logging.error("Error getting IAM Instance profile" + str(e))
                            return {
                                "statusCode": 500,
                                "body": json.dumps({"Error": str(e)}),
                            }
                        profile_iterator = instance_profile_detail["InstanceProfiles"]
                        for profile in range(len(profile_iterator)):
                            instance_profile = instance_profile_detail["InstanceProfiles"][profile]["Arn"]
                            ec2 = service_client.describe_instances(
                                Filters=[
                                    {"Name": "iam-instance-profile.arn", "Values": [instance_profile]}
                                ]
                            )
                            for reservation in ec2["Reservations"]:
                                for instance in reservation["Instances"]:
                                    instance_id = instance["InstanceId"]
                                    instance_region = instance["Placement"]["AvailabilityZone"][:-1]
                                    instance_name = next((tag["Value"] for tag in instance["Tags"] if tag["Key"] == "Name"), None)
                                    resourceIdIndex = combined_costs_df[combined_costs_df["lineItem/ResourceId"] == "i-0f5ee8dfeac1994a6"].index
                                    if len(resourceIdIndex) > 0:
                                        instance_cost = combined_costs_df.loc[resourceIdIndex[0], "lineItem/UnblendedCost"]
                                    else:
                                        instance_cost = 0.0
                                    service_cost = instance_cost
                                    instance_detail = {
                                        "ServiceName": "AmazonEC2",
                                        "ServiceCost": service_cost,
                                        "ResourceDetails": [{
                                            "ResourceName": instance_name,
                                            "ResourceId": instance_id,
                                            "ResourceRegion": instance_region,
                                            "InstanceCost": instance_cost
                                        }]
                                    }
                                    service_mapping.append(instance_detail)
                                    role_cost += service_cost
                    elif resource == "lambda":
                        lambda_mapping = []
                        lambda_functions = get_lambda_functions_in_role(role_name, combined_costs_df)
                        service_cost = sum(lambda_function.get('InstanceCost', 0) for lambda_function in lambda_functions)
                        if lambda_functions:
                            lambda_mapping.append({
                                "ServiceName": "AWSLambda",
                                "ServiceCost": service_cost,
                                "ResourceDetails": lambda_functions
                            })
                            role_cost += service_cost
                            service_mapping.extend(lambda_mapping)
                            
                            for lambda_function in lambda_functions:
                                resource_name = lambda_function.get('ResourceName')
                                cloudwatch_costs = get_cloudwatch_costs(resource_name, combined_costs_df)
                                cloudWatch_mapping = []
                                for cloudwatch in cloudwatch_costs:
                                    cloudWatch_mapping.append({
                                        "ServiceName": "AmazonCloudWatch",
                                        "ServiceCost": cloudwatch['InstanceCost'],
                                        "ResourceDetails": [cloudwatch]
                                    })
                                    role_cost += cloudwatch['InstanceCost']
                                    service_mapping.extend(cloudWatch_mapping)
                                    
                                # SNS Service    
                                sns_lambda_function = lambda_function.get('ResourceId')
                                sns_resource_details = get_sns_topic_for_lambda(sns_lambda_function, combined_costs_df)
                                sns_mapping = []
                                for sns in sns_resource_details:
                                    sns_mapping.append({
                                        "ServiceName": "AmazonSNS",
                                        "ServiceCost": sns['InstanceCost'],
                                        "ResourceDetails": [sns]
                                    })
                                    role_cost += sns['InstanceCost']
                                    service_mapping.extend(sns_mapping)
                                    
                                #SQS Service
                                sqs_lambda_function = lambda_function.get('ResourceId')
                                sqs_queue_arns = get_sqs_mappings_for_lambda(sqs_lambda_function, combined_costs_df)
                                sqs_mapping = []
                                for sqs in sqs_queue_arns:
                                    sqs_mapping.append({
                                        "ServiceName": "AWSQueueService",
                                        "ServiceCost": sqs['InstanceCost'],
                                        "ResourceDetails": [sqs]
                                    })
                                    role_cost += sqs['InstanceCost']
                                    service_mapping.extend(sqs_mapping)
                                    
                         
                    #EKS SERVICE                
                    associated_clusters = get_associated_eks_clusters(role_name, combined_costs_df)
                    eks_mapping = []
                    for eks in associated_clusters:
                        eks_mapping.append({
                            "ServiceName": "AmazonEKS",
                            "ServiceCost": eks['InstanceCost'],
                            "ResourceDetails": [eks]
                        })
                        role_cost += eks['InstanceCost']
                        service_mapping.extend(eks_mapping)
                        
                    
                    #ECS SERVICE
                    ecs_clusters = get_ecs_clusters(role_arn, combined_costs_df)
                    if ecs_clusters:
                        ecs_mapping = []
                        for ecs in ecs_clusters:
                            ecs_mapping.append({
                                "ServiceName": "AmazonECS",
                                "ServiceCost": ecs['InstanceCost'],
                                "ResourceDetails": [ecs]
                            })
                            role_cost += ecs['InstanceCost']
                            service_mapping.extend(ecs_mapping)
                    
                    
            role_mapping = {
                "Role": role_name,
                "Role_Region": role_region,
                "RoleCost": role_cost,
                "ServiceDetails": service_mapping
            }
            
            resource_mapping.append(role_mapping)

        registry = CollectorRegistry()
        gauge = Gauge(
            "IAM_Service_Cost_Detail",
            "IAM Service Cost Detail",
            ["role", "role_region", "role_cost", "service_name", "service_cost", "resource_name", "resource_id", "resource_region"],
            registry=registry,
        )

        for role_mapping in resource_mapping:
            role_arn = role_mapping["Role"]
            role_region = role_mapping["Role_Region"]
            role_cost = role_mapping["RoleCost"]
        
            for service_detail in role_mapping["ServiceDetails"]:
                service_name = service_detail.get("ServiceName", "")
                service_cost = service_detail.get("ServiceCost", 0)
        
                if "ResourceDetails" in service_detail and isinstance(service_detail["ResourceDetails"], list):
                    for resource_detail in service_detail["ResourceDetails"]:
                        resource_name = resource_detail.get("ResourceName", "")
                        resource_id = resource_detail.get("ResourceId", "")
                        resource_region = resource_detail.get("ResourceRegion", "")
                        instance_cost = resource_detail.get("InstanceCost", 0)
                            
                        gauge.labels(role_arn, role_region, role_cost, service_name, service_cost, resource_name, resource_id, resource_region).set(float(instance_cost))

        # Push the metrics to the Prometheus Gateway
        push_to_gateway(os.environ["prometheus_ip"], job="iam_cost_breakdown", registry=registry)

        return {
            'statusCode': 200,
            'body': json.dumps(resource_mapping)
        }
    except Exception as e:
        logging.error("An error occurred: " + str(e))
        return {
            "statusCode": 500,
            "body": json.dumps({"Error": str(e)})
        }