# External/Third-party Python Libraries
import dns.resolver
import dns.reversename


class ReverseDNS:
    """Resolves hostnames from IP addresses using a custom DNS resolver."""

    def __init__(self, nameservers: list[str] = None):
        self._resolver = dns.resolver.Resolver()
        self._resolver.nameservers = nameservers or ['1.1.1.1', '1.0.0.1']

    def lookup(self, target_ip: str):
        """Perform a reverse DNS lookup for the given IP address."""
        try:
            rev_name = dns.reversename.from_address(target_ip)
            if answer := self._resolver.resolve(rev_name, 'PTR'):
                if hostname := str(answer[0]).removesuffix('.'):
                    return hostname
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
            pass

        return target_ip  # No hostname found
