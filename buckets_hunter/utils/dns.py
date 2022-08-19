import logging

from dns import resolver

logger = logging.getLogger(__name__)


class DNSUtils:
    def __init__(self, name_server: str):
        self._dns_resolver = self._configure_dns_resolver(name_server)

    def _configure_dns_resolver(self, name_server: str):
        """Config a resolver for dns lookups."""
        try:
            dns_resolver = resolver.Resolver()
            dns_resolver.nameservers = [name_server]
            dns_resolver.timeout = 10
        except Exception as e:
            logger.error(e)
            dns_resolver = None
        return dns_resolver

    def dns_lookup(self, url: str) -> bool:
        try:
            self._dns_resolver.resolve(url)
        except resolver.NXDOMAIN:
            return False
        except resolver.Timeout:
            logger.error(f"DNS timeout error with {url=}")
            return False
        else:
            return True
