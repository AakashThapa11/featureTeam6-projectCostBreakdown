# Copyright (c) 2023, Xgrid Inc, https://xgrid.co

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#        http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import boto3
import csv
import io
import json
import logging
import zipfile
import os
import botocore
from prometheus_client import CollectorRegistry, Gauge, push_to_gateway


# Initialize the S3 client
try:
    s3 = boto3.client("s3")
except Exception as e:
    logging.error("Error creating boto3 client for s3: " + str(e))


def get_cost_data_from_s3(bucket_name, report_prefix):
    s3_client = boto3.client("s3")

    response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=report_prefix)

    report = []

    for obj in response.get("Contents", []):
        if obj["Key"].endswith(".zip"):
            response_zip = s3_client.get_object(Bucket=bucket_name, Key=obj["Key"])
            zip_bytes = response_zip["Body"].read()

            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zip_file:
                csv_filename = zip_file.namelist()[0]
                csv_data = zip_file.read(csv_filename).decode("utf-8")

        else:
            response = s3_client.get_object(Bucket=bucket_name, Key=obj["Key"])
            csv_data = response["Body"].read().decode("utf-8")

        reader = csv.DictReader(io.StringIO(csv_data))
        for row in reader:
            region = row.get("product/region")
            service = row.get("lineItem/ProductCode")
            resource = row.get("lineItem/ResourceId")
            cost = float(row.get("lineItem/UnblendedCost", 0))

            if cost <= 0:
                continue

            # Create a dictionary entry for each service
            entry = {
                "service": service,
                "region": region,
                "resource": resource,
                "cost": cost,
            }
            report.append(entry)

    return report


def lambda_handler(event, context):
    bucket_name = "reportbucketxc3"
    # Specify the prefix for the report files in your S3 bucket
    report_prefix = "xc3aakashreport/xc3aakash"

    # Fetch the account details and create the report from the AWS Cost and Usage Reports data in S3
    report = get_cost_data_from_s3(bucket_name, report_prefix)

    # Adding the extracted cost data to the Prometheus gauge as labels for service, region, and resource.
    try:
        registry = CollectorRegistry()
        gauge = Gauge(
            "Expensive_Services_Detail",
            "AWS Services Cost Detail",
            labelnames=["service", "region", "cost", "resource_name"],
            registry=registry,
        )

        for entry in report:
            service = entry["service"]
            region = entry["region"]
            resources = entry["resources"]
            total_service_cost = entry["cost"]

            for resource_data in resources:
                resource_name = resource_data["resource_name"]
                resource_cost = resource_data["resource_cost"]

                # Push resource-level metric
                gauge.labels(service, region, str(resource_cost), resource_name).set(
                    resource_cost
                )

            # Push total service cost metric
            gauge.labels(service, region, str(total_service_cost), "Total").set(
                total_service_cost
            )

        # Push the metrics to the Prometheus Gateway
        push_to_gateway(
            os.environ["prometheus_ip"],
            job="Expensive_Services_Detail",
            registry=registry,
        )

        # convert data to JSON
        json_data = json.dumps(report)

        # upload JSON file to S3 bucket
        bucket_name = os.environ["bucket_name"]
        key_name = f'{os.environ["expensive_service_prefix"]}/costandusagereport.json'
        try:
            s3.put_object(Bucket=bucket_name, Key=key_name, Body=json_data)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucket":
                raise ValueError(f"Bucket not found: {os.environ['bucket_name']}")
            elif e.response["Error"]["Code"] == "AccessDenied":
                raise ValueError(
                    f"Access denied to S3 bucket: {os.environ['bucket_name']}"
                )
            else:
                raise ValueError(f"Failed to upload data to S3 bucket: {str(e)}")
    except Exception as e:
        logging.error("Error initializing Prometheus Registry and Gauge: " + str(e))
        return {"statusCode": 500, "body": json.dumps({"Error": str(e)})}
    return {"statusCode": 200, "body": json.dumps(report)}
