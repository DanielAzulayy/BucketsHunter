import re
from typing import List

import requests

KEY_REGEX = re.compile(r"<(?:Key|Name)>(.*?)</(?:Key|Name)>")


def generate_bucket_permutations(
    keyword: str, mutations_wordlist: List[str]
) -> List[str]:
    bucket_names = []

    # "clean" keyword with no mutations.
    bucket_names.append(keyword)
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


def open_wordlist_file(wordlist_file):
    mutations_wordlist = []
    with open(wordlist_file, "r") as wordlist_file:
        mutations_wordlist = wordlist_file.read().splitlines()
    return mutations_wordlist


def get_bucket_files(bucket_url: str) -> List[str]:
    """Finds files inside an existing bucket."""
    response = requests.get(bucket_url)
    bucket_files = re.findall(KEY_REGEX, response.text)
    sub_regex = re.compile(r"(\?.*)")
    bucket_url = sub_regex.sub("", bucket_url)

    found_bucket_files = []
    if bucket_files is not None:
        for bucket_file in bucket_files:
            found_bucket_files.append(f"{bucket_url}/{bucket_file}")

    return found_bucket_files
