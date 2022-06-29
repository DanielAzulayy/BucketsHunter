import datetime
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Dict

from boto3 import client
from botocore import UNSIGNED
from botocore.client import ClientError, Config

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class S3BucketsScanner:
    def __init__(self):
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
            s3_client = None
            logger.error(e)

        return s3_client

    def scan_bucket(self, bucket_name: str) -> Dict[str, bool]:
        if not self._bucket_exists(bucket_name):
            return None

        return {
            "read": self._check_read_permission(bucket_name),
            "write": self._check_write_permission(bucket_name),
            "read_acp": self._check_read_acl_permission(bucket_name),
            "write_acp": self._check_write_acl_permission(bucket_name),
        }

    def _bucket_exists(self, bucket_name) -> False:
        try:
            self.s3_client.head_bucket(Bucket=bucket_name)
        except ClientError as err:
            logger.error(err)
            return False
        else:
            return True

    def _check_read_permission(self, bucket_name: str) -> bool:
        try:
            self.s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=0)
        except ClientError as err:
            logger.error(err)
            return False
        else:
            return True

    def _check_write_permission(self, bucket_name: str) -> bool:
        """Checking if writing a file is possible."""
        try:
            temp_write_file = (
                f"BucketHunter_{int(datetime.datetime.now().timestamp())}.txt"
            )
            # try to upload the file:
            self.s3_client.put_object(Bucket=bucket_name, Key=temp_write_file, Body=b"")
        except ClientError as err:
            logger.error(err)
            return False
        else:
            return True

    def _check_read_acl_permission(self, bucket_name: str) -> bool:
        """Checking if reading Access Control List is possible."""
        try:
            self.s3_client.get_bucket_acl(Bucket=bucket_name)
        except ClientError as err:
            logger.error(err)
            return False
        else:
            return True

    def _check_write_acl_permission(self, bucket_name: str) -> bool:
        """Checking if changing the Access Control List is possible.
        NOTE: This changes permissions to be public-read."""
        try:
            self.s3_client.put_bucket_acl(Bucket=bucket_name, ACL="public-read")
        except ClientError as err:
            logger.error(err)
            return False
        else:
            return True


def run(args, buckets_permutations: list):
    s3_bucket_scanner = S3BucketsScanner()

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(s3_bucket_scanner.scan_bucket, bucket_name): bucket_name
            for bucket_name in buckets_permutations
        }
        for future in futures:
            if future.result():
                print(future.result())