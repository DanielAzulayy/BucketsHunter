from typing import List


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
