import logging
import re
from concurrent.futures import ThreadPoolExecutor
from typing import List

import dns
import dns.resolver
import requests

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


STORAGE_ACCOUNT_URL = "{}.blob.core.windows.net"
CONTAINER_URL = "{}.blob.core.windows.net/{}"
STORAGE_ACCOUNT_REGEX = re.compile("[^a-zA-Z0-9]")


class AzureBucketsScanner:
    def __init__(self, name_server: str):
        self._name_server = name_server

        self.existing_storage_accounts = set()

    def find_existing_storage_accounts(self, storage_accounts_names: List[str]):
        for storage_account in storage_accounts_names:
            if not re.search(STORAGE_ACCOUNT_REGEX, storage_account):
                continue

            storage_account_url: str = STORAGE_ACCOUNT_URL.format(storage_account)
            if self._dns_lookup(storage_account_url):
                # needs the storage account only and not the full URL because of the container URL format.
                self.existing_storage_accounts.add(storage_account)

    def _dns_lookup(self, storage_account_url) -> bool:
        dns_resolver = self._initialize_dns_resolver()
        if dns_resolver is None:
            logger.error("Failed to initialize a dns resolver, quitting.")
            exit()  # can't brute force without a proper dns resolver.
        try:
            dns_resolver.resolve(storage_account_url)
        except dns.resolver.NXDOMAIN:  # doesn't exists
            return False
        except dns.resolver.Timeout:
            logger.error(f"DNS timeout error with {storage_account_url=}")
            return False
        return True

    def _initialize_dns_resolver(self):
        """Config a resolver for dns lookups."""
        try:
            dns_resolver = dns.resolver.Resolver()
            dns_resolver.nameservers = [self._name_server]
            dns_resolver.timeout = 10
        except Exception as e:
            logger.error(e)
            dns_resolver = None
        return dns_resolver

    def bruteforce_containers(self, container_directory: str) -> List[str]:
        found_containers = []
        for storage_account in self.existing_storage_accounts:
            container_url = f"https://{CONTAINER_URL.format(storage_account, container_directory)}/?restype=container&comp=list"
            if requests.get(container_url).status_code == 200:
                found_containers.append(container_url)

        return found_containers


def run(container_permutations: list, args):
    azure_scanner = AzureBucketsScanner(args.name_server)

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        executor.submit(
            azure_scanner.find_existing_storage_accounts, container_permutations
        )
        if azure_scanner.existing_storage_accounts is not None:
            bruteforce_futures = {
                executor.submit(
                    azure_scanner.bruteforce_containers, container_directory
                ): container_directory
                for container_directory in args.wordlist
            }
