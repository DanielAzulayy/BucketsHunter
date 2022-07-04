import argparse
import logging

import ujson
from BucketsHunter.conf.scan_config import Config
from BucketsHunter.modules.aws import aws_scanner
from BucketsHunter.modules.azure import azure_scanner
from BucketsHunter.modules.gcp import gcp_scanner
from BucketsHunter.utils.dns import DNSUtils
from BucketsHunter.utils.hunter_utils import (
    generate_bucket_permutations,
    open_wordlist_file,
)
from BucketsHunter.utils.notify import print_info

logger = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(
        description="BucketsHunter is an open source tool to find open buckets,\
        misconfigured permissions, and bucket's data."
    )
    parser.add_argument(
        "-k",
        "--keyword",
        help="Keyword to use for generating bucket permutations.",
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
        help="Add a custom wordlist to generate bucket permutations.",
        default="buckets_wordlist.txt",
    )
    parser.add_argument(
        "--disable-azure", action="store_true", help="Disable Azure scan."
    )
    parser.add_argument(
        "--disable-aws", action="store_true", help="Disable AWS S3 scan."
    )
    parser.add_argument("--disable-gcp", action="store_true", help="Disable GCP scan.")
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
            with open(
                "BucketsHunter/data/" + args.wordlist, "r", encoding="UTF-8"
            ) as wordlist_file:
                wordlist_file.read()
        except Exception as err:
            logger.error("Error while loading wordlist file %s", err)
            exit()
    if args.output_file:
        json_file_format = str(args.output_file).endswith(".json")
        if not json_file_format:
            logger.error(
                "BucketsHunter currently supports only JSON file as an output file."
            )
            exit()
    return args


def main():
    args = validate_args(args=parse_args())

    wordlist = open_wordlist_file(f"BucketsHunter/data/{args.wordlist}")
    scan_config = Config(
        dns_utils=DNSUtils(args.name_server),
        output_file=args.output_file,
        buckets_permutations=generate_bucket_permutations(args.keyword, wordlist),
        directory_wordlist=wordlist,  # currently using the same wordlist as bucket_permutations
        threads=args.threads,
    )
    print_info(
        f"Generated {len(scan_config.buckets_permutations)} bucket permutations."
    )

    final_scan_results = []
    if not args.disable_aws:
        print_info("Starting AWS buckets scan")
        final_scan_results += aws_scanner.run(scan_config)
    if not args.disable_azure:
        print_info("Starting Azure buckets scan")
        final_scan_results += azure_scanner.run(scan_config)
    if not args.disable_gcp:
        print_info("Starting GCP buckets scan")
        final_scan_results += gcp_scanner.run(scan_config)

    if final_scan_results:
        with open(args.output_file, "w") as json_file:
            json_file.write(
                ujson.dumps(final_scan_results, escape_forward_slashes=False)
            )


if __name__ == "__main__":
    main()
