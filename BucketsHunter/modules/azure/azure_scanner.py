import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

import requests
import ujson

from modules.azure.regions import AZURE_REGIONS
from utils.dns import DNSUtils

logging.basicConfig()
logger = logging.getLogger(__name__)

STORAGE_ACCOUNT_REGEX = re.compile("^[a-z0-9]{3,21}$")

STORAGE_ACCOUNT_URL = "{}.blob.core.windows.net"
CONTAINER_URL = "{}.blob.core.windows.net/{}"
WEBAPP_URL = "{}.azurewebsites.net"
AZURE_VM_URL = "{}.{}.cloudapp.azure.com"


class AzureBucketsScanner:
    def __init__(self, dns_utils: DNSUtils):
        self._dns_utils = dns_utils

        self.found_storage_accounts = set()

    def bruteforce_container_directory(self, container_directory: str) -> List[str]:
        found_containers_url = []
        for storage_account in self.found_storage_accounts:
            # format: storage_account.blob.core.windows.net/container_directory/?restype=container&comp=list
            container_url = f"https://{CONTAINER_URL.format(storage_account, container_directory)}?restype=container&comp=list"
            if requests.get(container_url).status_code == 200:
                found_containers_url.append(container_url)
        return found_containers_url

    def scan_storage_account(self, bucket_name):
        """Finds Azure storage accounts, only possible to check if user exists by dns lookup."""
        if re.search(STORAGE_ACCOUNT_REGEX, bucket_name) is not None:
            storage_account_url = STORAGE_ACCOUNT_URL.format(bucket_name)
            if self._dns_utils.dns_lookup(url=storage_account_url):
                self.found_storage_accounts.add(bucket_name)
                return storage_account_url
        return None

    def scan_web_apps(self, bucket_name: str):
        """finding azure websites by bruteforce."""
        web_app_url = WEBAPP_URL.format(bucket_name)
        if self._dns_utils.dns_lookup(web_app_url):
            return web_app_url
        return None

    def scan_azure_vm(self, bucket_name: str):
        found_vms = []
        for region in AZURE_REGIONS:
            # format: {bucket_name}.{region}.cloudapp.azure.com
            azure_vm_url = AZURE_VM_URL.format(bucket_name, region)
            if self._dns_utils.dns_lookup(azure_vm_url):
                found_vms.append(azure_vm_url)
        return found_vms


def run(scan_config):
    azure_scanner = AzureBucketsScanner(scan_config.dns_utils)

    with ThreadPoolExecutor(max_workers=scan_config.threads) as executor:
        print("Scanning for Azure Storage Accounts")
        storage_account_features = {
            executor.submit(azure_scanner.scan_storage_account, bucket_name)
            for bucket_name in scan_config.buckets_permutations
        }
        for feature in as_completed(storage_account_features):
            if feature.result():
                print(f"Storage account found: {feature.result()}")
        print("\n")

        print("Bruteforce Azure containers directories")
        if azure_scanner.found_storage_accounts is not None:
            bruteforce_dir_futures = {
                executor.submit(
                    azure_scanner.bruteforce_container_directory, container_directory
                )
                for container_directory in scan_config.directory_wordlist
            }
            for feature in as_completed(bruteforce_dir_futures):
                if feature.result():
                    print(f"Container directory found: {feature.result()}")
        print("\n")

        print("Scanning for Azure Web Apps")
        azure_app_features = {
            executor.submit(azure_scanner.scan_web_apps, bucket_name)
            for bucket_name in scan_config.buckets_permutations
        }
        for feature in as_completed(azure_app_features):
            if feature.result():
                print(f"Website found: {feature.result()}")
        print("\n")

        print("Scanning for Azure VMs across all regions")
        azure_vms_features = {
            executor.submit(azure_scanner.scan_azure_vm, bucket_name)
            for bucket_name in scan_config.buckets_permutations
        }
        for feature in as_completed(azure_vms_features):
            if feature.result():
                print(f"VM found: {feature.result()}")
