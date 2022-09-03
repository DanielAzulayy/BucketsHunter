import os
import re
from typing import List, Iterator

import requests

KEY_REGEX = re.compile(r"<(?:Key|Name)>(.*?)</(?:Key|Name)>")


def generate_bucket_permutations(keyword: str, mutations) -> Iterator:
    bucket_names = [keyword]
    for mutation in list(mutations):
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

    return iter(bucket_names)



def get_bucket_files(bucket_url: str) -> List[str]:
    """Finds files inside an existing bucket."""
    response = requests.get(bucket_url)
    bucket_files = re.findall(KEY_REGEX, response.text)
    sub_regex = re.compile(r"(\?.*)")
    bucket_url = sub_regex.sub("", bucket_url)

    found_bucket_files = []
    if bucket_files is not None:
        found_bucket_files.extend(
            f"{bucket_url}/{bucket_file}" for bucket_file in bucket_files
        )

    return found_bucket_files
