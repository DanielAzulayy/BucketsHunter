import argparse
import logging

from conf import Config
from modules.aws import aws_scanner
from modules.azure import azure_scanner
from utils.buckets_hunter_utils import (configure_dns_resolver,
                                        generate_bucket_permutations)

logger = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(
        description="BucketsHunter is an open source tool to find open buckets, misconfigured permissions, and bucket's data."
    )
    parser.add_argument(
        "-k",
        "--keyword",
        help="Keyword to use for generating buckets names.",
        required=True,
    )
    parser.add_argument(
        "-b",
        "--bruteforce",
        help="Scan option to bruteforce subdomains",
        action="store_true",
    )
    parser.add_argument(
        "-w",
        "--wordlist",
        help="Add a custom wordlist to generate permutations.",
        default="fuzz_wordlist.txt",
    )
    parser.add_argument(
        "--disable-azure", action="store_true", help="Disable Azure scan."
    )
    parser.add_argument(
        "--disable-aws", action="store_true", help="Disable Amazon scan."
    )
    parser.add_argument(
        "--disable-gcp", action="store_true", help="Disable Google scan."
    )
    parser.add_argument(
        "-t",
        "--threads",
        default=10,
        help="Number of threads to use. Default: 10.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Save the results to a JSON file.",
        dest="output_file",
        default=False,
    )
    parser.add_argument(
        "-n",
        "--nameservers",
        help="Nameserver to configure the dns resolver with",
        dest="name_server",
        default="1.1.1.1",
    )

    return parser.parse_args()


def validate_args(args):
    if args.wordlist:
        try:
            with open("BucketsHunter/data/" + args.wordlist, "r") as wordlist_file:
                wordlist_file.read()
        except Exception as err:
            logger.error(f"Error while loading wordlist file: {err}")
    if args.output_file:
        json_file_format = str(args.output_file).endswith(".json")
        if not json_file_format:
            logger.error(
                "BucketsHunter currently supports only JSON file as an output file."
            )
    return args


def main():
    args = validate_args(args=parse_args())

    scan_config = Config(
        dns_resolver=configure_dns_resolver(args.name_server),
        output_file=args.output_file,
        buckets_permutations=generate_bucket_permutations(
            args.keyword, "BucketsHunter/data/" + args.wordlist
        ),
        threads=args.threads,
    )

    if not args.disable_aws:
        logger.info("Starting AWS buckets scan")
        aws_scanner.run(scan_config)
    if not args.disable_azure:
        logger.info("Starting Azure buckets scan")
        azure_scanner(scan_config)
    # if not args.disable_gcp:
    #     logger.info("Starting GCP buckets scan")
    #     gcp_scanner(buckets_permutations, args)


if __name__ == "__main__":
    main()
