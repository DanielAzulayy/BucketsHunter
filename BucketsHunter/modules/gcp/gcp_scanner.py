from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


class GCPBucketsScanner:
    def __init__(self) -> None:
        pass

    def scan_bucket_permissions(self, bucket_name: str):
        bucket_url = f"https://storage.googleapis.com/{bucket_name}"
        if not self._bucket_exists(bucket_url):
            return None

        permissions_jres = requests.get(
            f"https://www.googleapis.com/storage/v1/b/{bucket_name}/iam/testPermissions?permissions=storage.buckets.delete&permissions=storage.buckets.get&permissions=storage.buckets.getIamPolicy&permissions=storage.buckets.setIamPolicy&permissions=storage.buckets.update&permissions=storage.objects.create&permissions=storage.objects.delete&permissions=storage.objects.get&permissions=storage.objects.list&permissions=storage.objects.update"
        ).json()
        found_permissions = permissions_jres.get("permissions")
        if found_permissions is not None:
            return {
                "bucket_url": bucket_url,
                "bucket_readable": self._check_read_permission(found_permissions),
                "bucket_writeable": self._check_write_permission(found_permissions),
                "bucket_listable": self._check_list_permission(found_permissions),
                "bucket_privesc": self._check_privesc_permission(found_permissions),
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

    with ThreadPoolExecutor(max_workers=scan_config.threads) as executor:
        gcp_permissions_features = {
            executor.submit(gcp_scanner.scan_bucket_permissions, bucket_name)
            for bucket_name in scan_config.buckets_permutations
        }
        for feature in as_completed(gcp_permissions_features):
            if feature.result():
                print(f"{feature.result()}")