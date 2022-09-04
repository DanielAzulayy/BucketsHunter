import argparse
import importlib
import os

import ujson
from loguru import logger

from buckets_hunter.conf.scan_config import Config
from buckets_hunter.modules.aws import aws_scanner
from buckets_hunter.modules.azure import azure_scanner
from buckets_hunter.modules.gcp import gcp_scanner
from buckets_hunter.utils import hunter_utils
from buckets_hunter.utils.dns import DNSUtils
from buckets_hunter.utils.hunter_utils import generate_bucket_permutations

SUPPORTED_PLATFORMS = ["aws", "azure", "gcp"]


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
        "-w",
        "--wordlist",
        help="Add a custom wordlist to generate bucket permutations.",
        default="buckets_wordlist.txt",
    )
    parser.add_argument(
        "-p",
        "--platform",
        dest="platform",
        help="Platform for scanning",
        type=str,
        default="all",
    )
    parser.add_argument(
        "-t",
        "--threads",
        default=10,
        type=int,
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
    if args.output_file:
        if not (file_format_input := str(args.output_file).endswith(".json")):
            logger.error("BucketsHunter supports JSON files only.")
            exit()
    if args.platform != "all" and args.platform not in SUPPORTED_PLATFORMS:
        logger.error(
            f"BucketsHunter doesn't support {args.platform} as a platform. {SUPPORTED_PLATFORMS=}"
        )
        exit()
    return args


def main():
    args = validate_args(args=parse_args())

    # pypi import wordlist (.txt files) - must
    this_dir, _ = os.path.split(__file__)
    wordlist_path= os.path.join(this_dir, "data", args.wordlist)
    with open(wordlist_path, "r", encoding="UTF-8") as wordlist_file:
        mutations_wordlist = iter(wordlist_file.read().splitlines())

    scan_config = Config(
        dns_utils=DNSUtils(args.name_server),
        output_file=args.output_file,
        buckets_permutations=generate_bucket_permutations(
            args.keyword, mutations_wordlist
        ),
        threads=args.threads,
    )
    logger.info("Generated bucket permutations.")

    final_scan_results = []
    if args.platform != "all":
        scan_platform_module = importlib.import_module(
            f"buckets_hunter.modules.{args.platform}.{args.platform}_scanner"
        )
        logger.info(f"Starting {args.platform} buckets scan")
        final_scan_results = scan_platform_module.run(scan_config)
    else:
        logger.info("Starting AWS buckets scan")
        final_scan_results += aws_scanner.run(scan_config)

        logger.info("Starting Azure buckets scan")
        final_scan_results += azure_scanner.run(scan_config)

        logger.info("Starting GCP buckets scan")
        final_scan_results += gcp_scanner.run(scan_config)

    if final_scan_results and args.output_file:
        with open(args.output_file, "w") as json_file:
            logger.info(f"Writing to: {args.output_file}")
            ujson.dump(
                final_scan_results, json_file, escape_forward_slashes=False, indent=4
            )
    logger.info("Finished with scanning.")


if __name__ == "__main__":
    main()
