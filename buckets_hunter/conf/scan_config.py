from dataclasses import dataclass
from typing import List, Optional

from buckets_hunter.utils.dns import DNSUtils


@dataclass
class Config:
    """Config dataclass in order to create relevant data for all scans
    - dns_utils: dns utilities for dns lookups
    - output_file: output file - saving scan results
    - buckets_permutations: lists with different buckets to bruteforce
    - directory_wordlist: bucket directory bruteforce
    """

    dns_utils: DNSUtils = None
    output_file: Optional[str] = None
    buckets_permutations: List[str] = None
    directory_wordlist: List[str] = None
    threads: Optional[int] = None
