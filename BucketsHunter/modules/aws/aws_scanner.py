import datetime
import logging
from concurrent.futures import ThreadPoolExecutor

from boto3 import client
from botocore import UNSIGNED
from botocore.client import ClientError, Config

AWS_URL = "{}.s3.amazonaws.com"
logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class S3BucketsScanner:
    def __init__(self, dns_resolver):
        self._dns_resolver = dns_resolver

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

    def scan_bucket(self, bucket_name: str) -> dict:
        if not self._bucket_exists(bucket_name):
            return None
        
        return {
            "bucket_url": AWS_URL.format(bucket_name),
            "bucket_readable": self._check_read_permission(bucket_name),
            "bucket_writeable": self._check_write_permission(bucket_name),
            "bucket_read_acp": self._check_read_acl_permission(bucket_name),
            "bucket_write_acp": self._check_write_acl_permission(bucket_name),
        }

    def _bucket_exists(self, bucket_name) -> False:
        try:
            self.s3_client.head_bucket(Bucket=bucket_name)
        except ClientError as err:
            return False
        else:
            return True

    def _check_read_permission(self, bucket_name: str) -> bool:
        try:
            self.s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=0)
        except ClientError as err:
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
        except ClientError as err:
            return False
        else:
            # successful upload, delete the file:
            self.s3_client.delete_object(Bucket=bucket_name, Key=temp_write_file)
            return True

    def _check_read_acl_permission(self, bucket_name: str) -> bool:
        """Checks if reading Access Control List is possible."""
        try:
            self.s3_client.get_bucket_acl(Bucket=bucket_name)
        except ClientError as err:
            return False
        else:
            return True

    def _check_write_acl_permission(self, bucket_name: str) -> bool:
        """Checks if changing the Access Control List is possible.
        NOTE: This changes permissions to be public-read."""
        try:
            self.s3_client.put_bucket_acl(Bucket=bucket_name, ACL="public-read")
        except ClientError as err:
            return False
        else:
            return True

    def scan_aws_apps(self, bucket_name: str):
        ...


def run(scan_config):
    s3_bucket_scanner = S3BucketsScanner(scan_config.dns_resolver)

    with ThreadPoolExecutor(max_workers=scan_config.threads) as executor:
        futures = {
            executor.submit(s3_bucket_scanner.scan_bucket, bucket_name): bucket_name
            for bucket_name in scan_config.buckets_permutations
        }
        for future in futures:
            if future.result():
                print(future.result())

        # aws_apps_feature = {
        #     executor.submit(s3_bucket_scanner.scan_aws_apps, bucket_name): bucket_name
        #     for bucket_name in scan_config.buckets_permutations
        # }
