import argparse
import importlib
from xmlrpc.client import escape

import ujson
from loguru import logger

from BucketsHunter.conf.scan_config import Config
from BucketsHunter.modules.aws import aws_scanner
from BucketsHunter.modules.azure import azure_scanner
from BucketsHunter.modules.gcp import gcp_scanner
from BucketsHunter.utils.dns import DNSUtils
from BucketsHunter.utils.hunter_utils import (generate_bucket_permutations,
                                              open_wordlist_file)


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
    if args.platform != "all":
        platforms = ["aws", "azure", "gcp"]
        matching = [platform for platform in platforms if platform == args.platform]
        if not matching:
            logger.error(
                f"BucketsHunter doesn't support {args.platform} as a platform."
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
    logger.info(
        f"Generated {len(scan_config.buckets_permutations)} bucket permutations."
    )

    final_scan_results = []
    if args.platform != "all":
        # user provided input, instead of bunch of if else statements.
        scan_platform_module = importlib.import_module(
            f"BucketsHunter.modules.{args.platform}.{args.platform}_scanner"
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
            ujson.dump(final_scan_results, json_file, escape_forward_slashes=False, indent=4)

    logger.info("Finished with scanning.")


if __name__ == "__main__":
    main()
