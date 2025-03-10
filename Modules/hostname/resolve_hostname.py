import dns.resolver
import dns.reversename

def resolve_hostname(ip: str):
    """Resolve the hostname for the given IP address using a custom DNS server."""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['1.1.1.1', '1.0.0.1']

    try:
        rev_name = dns.reversename.from_address(ip)
        if answer := resolver.resolve(rev_name, 'PTR'):
            if hostname := str(answer[0]).removesuffix('.'):
                return hostname
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
        pass

    return ip  # No hostname found
