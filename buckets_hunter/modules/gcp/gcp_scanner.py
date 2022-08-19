from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Union

import requests
from buckets_hunter.utils import hunter_utils
from buckets_hunter.utils.notify import print_service
from loguru import logger


class GCPBucketsScanner:
    PLATFORM = "Gcp"

    def __init__(self):
        pass

    def scan_bucket_permissions(
        self, bucket_name: str
    ) -> Dict[str, Union[str, Dict[str, bool]]]:
        bucket_url = f"https://www.googleapis.com/storage/v1/b/{bucket_name}"
        if not self._bucket_exists(bucket_url):
            return None

        permissions_jres = requests.get(
            f"https://www.googleapis.com/storage/v1/b/{bucket_name}/iam/testPermissions?permissions=storage.buckets.delete&permissions=storage.buckets.get&permissions=storage.buckets.getIamPolicy&permissions=storage.buckets.setIamPolicy&permissions=storage.buckets.update&permissions=storage.objects.create&permissions=storage.objects.delete&permissions=storage.objects.get&permissions=storage.objects.list&permissions=storage.objects.update"
        ).json()
        found_permissions = permissions_jres.get("permissions")
        if found_permissions is not None:
            return {
                "platform": GCPBucketsScanner.PLATFORM,
                "service": "GCP",
                "bucket": bucket_url,
                "permissions": {
                    "readable": self._check_read_permission(found_permissions),
                    "writeable": self._check_write_permission(found_permissions),
                    "listable": self._check_list_permission(found_permissions),
                    "privesc": self._check_privesc_permission(found_permissions),
                },
                "files": hunter_utils.get_bucket_files(bucket_url),
            }
        return None

    def _bucket_exists(self, bucket_url):
        bucket_response = requests.get(bucket_url)
        return bucket_response.status_code not in [400, 404, 500]

    def _check_read_permission(self, permissions_res: list) -> bool:
        return "storage.objects.get" in permissions_res

    def _check_write_permission(self, permissions_res: list) -> bool:
        """Checks for write permissions."""
        return (
            "storage.objects.create" in permissions_res
            or "storage.objects.delete" in permissions_res
            or "storage.objects.update" in permissions_res
        )

    def _check_list_permission(self, permissions_res: list) -> bool:
        return "storage.objects.list" in permissions_res

    def _check_privesc_permission(self, permissions_res: list) -> bool:
        return "storage.buckets.setIamPolicy" in permissions_res


def run(scan_config):
    gcp_scanner = GCPBucketsScanner()
    gcp_scan_results = []

    with ThreadPoolExecutor(max_workers=scan_config.threads) as executor:
        found_buckets_futures = {
            executor.submit(gcp_scanner.scan_bucket_permissions, bucket_name)
            for bucket_name in scan_config.buckets_permutations
        }

        for feature in as_completed(found_buckets_futures):
            try:
                gcp_scan_result = feature.result()
            except Exception as err:
                logger.error(err)
            else:
                if gcp_scan_result:
                    print_service(gcp_scan_result)
                    gcp_scan_results.append(gcp_scan_result)

    return gcp_scan_results