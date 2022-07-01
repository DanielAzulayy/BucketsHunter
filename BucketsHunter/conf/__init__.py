from dataclasses import dataclass
from typing import List, Optional
from dns.resolver import Resolver


@dataclass
class Config:
    """Config dataclass in order to create relevant data for all scans
    - dns_resolver: dns resolver for dns lookups
    - output_file: output file - saving scan results
    - buckets_permutations: lists with different buckets to bruteforce
    """

    dns_resolver: Resolver = None
    output_file: Optional[str] = None
    buckets_permutations: List[str] = None
    directory_wordlist: List[str] = None
    threads: Optional[int] = None
