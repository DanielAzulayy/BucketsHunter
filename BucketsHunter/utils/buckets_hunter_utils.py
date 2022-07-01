import logging
from typing import List

import dns
from dns.resolver import Resolver

logger = logging.getLogger(__name__)


def generate_bucket_permutations(keyword: str, mutations_wordlist_file) -> List[str]:
    bucket_names = []
    with open(mutations_wordlist_file, "r") as wordlist_file:
        mutations_wordlist = wordlist_file.read().splitlines()

    for mutation in mutations_wordlist:
        # format ex: {keyword}-{mutation}.s3.amazonaws.com
        bucket_names.append(f"{keyword}-{mutation}")

        # format ex: {keyword}_{mutation}.s3.amazonaws.com
        bucket_names.append(f"{keyword}_{mutation}")

        # format ex: {keyword}{mutation}.s3.amazonaws.com
        bucket_names.append(f"{keyword}{mutation}")

        # reversed:
        bucket_names.append(f"{mutation}-{keyword}")
        bucket_names.append(f"{mutation}_{keyword}")
        bucket_names.append(f"{mutation}{keyword}")

    return bucket_names


def configure_dns_resolver(name_server: str):
    """Config a resolver for dns lookups."""
    try:
        dns_resolver = Resolver()
        dns_resolver.nameservers = [name_server]
        dns_resolver.timeout = 10
    except Exception as e:
        logger.error(e)
        dns_resolver = None

    return dns_resolver
