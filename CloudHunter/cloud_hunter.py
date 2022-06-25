import argparse


def parse_args():
    parser = argparse.ArgumentParser(
        description="CloudHunter is an open source tool to find open buckets, permissions"
    )
    parser.add_argument(
        "-d", "--domain", help="Domain to scan for open buckets.", required=True
    )
    parser.add_argument(
        "-b",
        "--bruteforce",
        help="Scan option to bruteforce subdomains",
        action="store_true",
    )
    parser.add_argument(
        "-a",
        "--all",
        help="Scan on all platforms (AWS, Azure, and GCP)",
        action="store_true",
    )
    parser.add_argument(
        "-w",
        "--wordlist",
        help="Add a custom wordlist to generate permutations.",
        default="default_wordlist.txt",
    )
    parser.add_argument(
        "-p",
        "--platform",
        help="Scan for a specific platform, for example only on AWS.",
        type=str,
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Save the results to a JSON file.",
        default=False,
    )

    args = parser.parse_args()
    return args


def main():
    args = parse_args()


if __name__ == "__main__":
    main()