import datetime
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from boto3 import client
from botocore import UNSIGNED
from botocore.client import ClientError, Config
from utils.dns import DNSUtils

S3_BUCKET_URL = "{}.s3.amazonaws.com"
AWS_APPS_URL = "{}.awsapps.com"

logger = logging.getLogger(__name__)


class S3BucketsScanner:
    def __init__(self, dns_utils: DNSUtils):
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
        except Exception as e:
            logger.error(e)
            exit()

        return s3_client

    def scan_aws_apps(self, bucket_name: str):
        aws_app_url = AWS_APPS_URL.format(bucket_name)
        if self._dns_utils.dns_lookup(aws_app_url):
            return aws_app_url
        return None

    def scan_bucket_permissions(self, bucket_name: str) -> dict:
        if not self._bucket_exists(bucket_name):
            return None

        return {
            "bucket_url": S3_BUCKET_URL.format(bucket_name),
            "bucket_readable": self._check_read_permission(bucket_name),
            "bucket_writeable": self._check_write_permission(bucket_name),
            "bucket_read_acp": self._check_read_acl_permission(bucket_name),
            "bucket_write_acp": self._check_write_acl_permission(bucket_name),
        }

    def _bucket_exists(self, bucket_name) -> False:
        try:
            self.s3_client.head_bucket(Bucket=bucket_name)
        except ClientError as _:
            return False
        else:
            return True

    def _check_read_permission(self, bucket_name: str) -> bool:
        try:
            self.s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=0)
        except ClientError as _:
            return False
        else:
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
        else:
            return True

    def _check_write_acl_permission(self, bucket_name: str) -> bool:
        """Checks if changing the Access Control List is possible.
        NOTE: This changes permissions to be public-read."""
        try:
            self.s3_client.put_bucket_acl(Bucket=bucket_name, ACL="public-read")
        except ClientError as _:
            return False
        else:
            return True


def run(scan_config):
    s3_bucket_scanner = S3BucketsScanner(scan_config.dns_utils)

    with ThreadPoolExecutor(max_workers=scan_config.threads) as executor:
        found_buckets_futures = {
            executor.submit(s3_bucket_scanner.scan_bucket_permissions, bucket_name)
            for bucket_name in scan_config.buckets_permutations
        }
        for feature in as_completed(found_buckets_futures):
            if feature.result():
                print(f"S3 bucket found: {feature.result()}\n")
