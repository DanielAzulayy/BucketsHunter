import argparse
import logging

logger = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(
        description="CloudHunter is an open source tool to find open buckets, permissions"
    )
    parser.add_argument(
        "-k",
        "--keyword",
        help="Keyword to use for generating buckets names.",
        required=False,
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
        default="default_wordlist.txt",
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
        "-o",
        "--output",
        help="Save the results to a JSON file.",
        default=False,
    )
    return parser.parse_args()


def _validate_args(args):
    if args.wordlist:
        try:
            with open(args.wordlist, "r") as wordlist_file:
                wordlist_file.read()
        except Exception as err:
            logging.error(f"Error while loading wordlist file: {err}")
            exit()
    if args.output:
        json_file_format = str(args.output).endswith(".json")
        if not json_file_format:
            logging.error("CloudHunter supports only JSON file as an output file.")
            exit()


def main():
    args = parse_args()
    _validate_args(args)


if __name__ == "__main__":
    main()