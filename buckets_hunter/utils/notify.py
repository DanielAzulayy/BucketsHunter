class Colors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def print_open_bucket(result):
    msg = f"""{Colors.OKCYAN} Open {result['platform']} {result['service']} 
        bucket: {result['bucket']}
        permissions:  {result['permissions']}
        files:\t{(prettify_files(result['files']))}
        """
    print(msg)


def prettify_files(urls):
    return "\n\t\t".join(urls)


def print_service(result):
    msg = f"""{Colors.OKCYAN} {result['platform']} service found:
        service: {result['service']}
        bucket: {result['bucket']}
        """
    print(msg)
