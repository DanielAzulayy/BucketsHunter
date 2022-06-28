from typing import List


def generate_bucket_permutations(keyword: str, mutations_wordlist_file) -> List[str]:
    bucket_names = []

    with open(mutations_wordlist_file, 'r') as wordlist_file:
        mutations_wordlist = wordlist_file.read()

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
