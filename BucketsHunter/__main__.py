import sys

if __name__ == "__main__":
    python_version = sys.version.split()[0]
    if sys.version_info < (3, 6):
        print(
            f"BucketsHunter requires Python 3.6+\n You are using Python {python_version}, which is not supported by BucketsHunter."
        )
        exit(1)

    import buckets_hunter
    buckets_hunter.main()