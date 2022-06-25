import argparse


async def start():
    parser = argparse.ArgumentParser(
        description="CloudHunter is an open source tool to find open buckets, permissions, an"
    )
    parser.add_argument(
        "-d", "--domain", help="Domain to scan for open buckets.", required=True
    )
    parser.add_argument(
        "-a", "--all", help="Scan on all platforms (AWS, Azure, and GCP)"
    )
    parser.add_argument(
        "-p",
        "--platform",
        help="Scan for a specific platform, for example only on AWS.",
        type="str",
    )
    parser.add_argument(
        "-o", "--output", help="Save the results to a JSON file.", type="str"
    )
