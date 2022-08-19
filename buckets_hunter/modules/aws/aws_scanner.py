import datetime
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Union

from boto3 import client
from botocore import UNSIGNED
from botocore.client import ClientError, Config
from buckets_hunter.utils import dns, hunter_utils
from buckets_hunter.utils.notify import print_open_bucket, print_service
from loguru import logger

S3_BUCKET_URL = "{}.s3.amazonaws.com"
AWS_APPS_URL = "{}.awsapps.com"


class S3BucketsScanner:
    PLATFORM = "AWS"

    def __init__(self, dns_utils: dns.DNSUtils):
        self._dns_utils = dns_utils

        self.s3_client = self._initialize_s3_client()

    def _initialize_s3_client(self) -> client:
        try:
            s3_client = client(
                "s3",  # type of client
                config=Config(signature_version=UNSIGNED),  # without creds
                use_ssl=True,
                verify=True,
            )
        except Exception as err:
            sys.exit(err)
        return s3_client

    def scan_aws_apps(self, bucket_name: str) -> Dict[str, str]:
        aws_app_url = AWS_APPS_URL.format(bucket_name)
        if self._dns_utils.dns_lookup(aws_app_url):
            return {
                "platform": S3BucketsScanner.PLATFORM,
                "service": "AWS apps",
                "bucket": aws_app_url,
            }
        return None

    def scan_bucket_permissions(
        self, bucket_name: str
    ) -> Dict[str, Union[str, Dict[str, bool]]]:
        if not self._bucket_exists(bucket_name):
            return None

        bucket_url = S3_BUCKET_URL.format(bucket_name)
        return {
            "platform": S3BucketsScanner.PLATFORM,
            "service": "S3",
            "bucket": bucket_url,
            "permissions": {
                "readable": self._check_read_permission(bucket_name),
                "writeable": self._check_write_permission(bucket_name),
                "acp_readable": self._check_read_acl_permission(bucket_name),
                "acp_writeable": self._check_write_acl_permission(bucket_name),
            },
            "files": hunter_utils.get_bucket_files(f"https://{bucket_url}"),
        }

    def _bucket_exists(self, bucket_name) -> False:
        try:
            self.s3_client.head_bucket(Bucket=bucket_name)
        except ClientError as _:
            return False
        return True

    def _check_read_permission(self, bucket_name: str) -> bool:
        try:
            self.s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=0)
        except ClientError as _:
            return False
        return True

    def _check_write_permission(self, bucket_name: str) -> bool:
        """Checks if writing a file to bucket is possible."""
        try:
            temp_write_file = (
                f"BucketHunter_{int(datetime.datetime.now().timestamp())}.txt"
            )
            # try to upload the file:
            self.s3_client.put_object(Bucket=bucket_name, Key=temp_write_file, Body=b"")
        except ClientError as _:
            return False
        else:
            # successful upload, delete the file:
            self.s3_client.delete_object(Bucket=bucket_name, Key=temp_write_file)
            return True

    def _check_read_acl_permission(self, bucket_name: str) -> bool:
        """Checks if reading Access Control List is possible."""
        try:
            self.s3_client.get_bucket_acl(Bucket=bucket_name)
        except ClientError as _:
            return False
        return True

    def _check_write_acl_permission(self, bucket_name: str) -> bool:
        """Checks if changing the Access Control List is possible.
        NOTE: This changes permissions to be public-read."""
        try:
            self.s3_client.put_bucket_acl(Bucket=bucket_name, ACL="public-read")
        except ClientError as _:
            return False
        return True


def run(scan_config):
    s3_bucket_scanner = S3BucketsScanner(scan_config.dns_utils)
    aws_scan_results = []

    with ThreadPoolExecutor(max_workers=scan_config.threads) as executor:
        found_buckets_futures = {
            executor.submit(s3_bucket_scanner.scan_bucket_permissions, bucket_name)
            for bucket_name in scan_config.buckets_permutations
        }
        for feature in as_completed(found_buckets_futures):
            try:
                s3_scan_result = feature.result()
            except Exception as err:
                logger.error(err)
            else:
                if s3_scan_result:
                    print_open_bucket(s3_scan_result)
                    aws_scan_results.append(s3_scan_result)

        found_apps_futures = {
            executor.submit(s3_bucket_scanner.scan_aws_apps, bucket_name)
            for bucket_name in scan_config.buckets_permutations
        }
        for feature in as_completed(found_apps_futures):
            try:
                aws_app_scan_result = feature.result()
            except Exception as err:
                logger.error(err)
            else:
                if aws_app_scan_result:
                    print_service(aws_app_scan_result)
                    aws_scan_results.append(aws_app_scan_result)

    return aws_scan_results
