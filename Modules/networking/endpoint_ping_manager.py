# Standard Python Libraries
import sys
import time
import threading
from pathlib import Path
from requests import exceptions
from typing import Optional, NamedTuple, Dict
from urllib.parse import urlparse
from dataclasses import dataclass, field

# Local Python Libraries (Included with Project)
parent_dir = Path(__file__).resolve().parent.parent
sys.path.append(str(parent_dir))
from Modules.networking.unsafe_https import s
from Modules.constants.standard import RE_BYTES_PATTERN, RE_PACKET_STATS_PATTERN, RE_RTT_STATS_PATTERN


class InvalidPingResult(Exception):
    """Exception raised when the parsed ping result contains invalid or missing data."""

    def __init__(self, ip: str, response_content: str, ping_result: "PingResult"):
        attributes = "\n".join(f"{attr}={getattr(ping_result, attr)}"
                               for attr in ping_result._fields)
        super().__init__(f"Invalid ping result for {ip}:\n"
                         f"Response: {response_content}\n"
                         f"{attributes}")

class AllEndpointsExhausted(Exception):
    """Exception raised when all endpoints have been exhausted."""
    pass


@dataclass
class EndpointInfo:
    url: str
    calls: int = 0
    failures: int = 0
    total_time: float = 0.0
    cooldown_until: float = 0.0
    failed_ips: Dict[str, int] = field(default_factory=dict)

    def update_success(self, duration: float, ip: str):
        self.calls += 1
        self.total_time += duration
        self.cooldown_until = 0.0

        if ip in self.failed_ips:
            del self.failed_ips[ip]  # Remove from failed URLs if previously failed

    def update_failure(self, duration: float, cooldown: float, ip: str):
        self.calls += 1
        self.failures += 1
        self.total_time += duration
        self.cooldown_until = time.monotonic() + cooldown

        # Increment failure count for this specific ip
        self.failed_ips[ip] = self.failed_ips.get(ip, 0) + 1

    def average_time(self):
        if self.calls > 0:
            return self.total_time / self.calls
        return float("inf")

    def score(self, now: float):
        # If still cooling down, assign an infinite score.
        if now < self.cooldown_until:
            return float("inf")
        penalty = self.failures * 1000  # Adjust penalty factor as needed.
        return self.average_time() + penalty

class PingResult(NamedTuple):
    ping_times:          list[float]
    packets_transmitted: Optional[int]
    packets_received:    Optional[int]
    packet_loss:         Optional[float]
    packet_errors:       Optional[int]
    rtt_min:             Optional[float]
    rtt_avg:             Optional[float]
    rtt_max:             Optional[float]
    rtt_mdev:            Optional[float]

    def is_invalid(self, ping_response: str):
        """
        Returns True if the ping data is invalid (missing critical information).
        """
        return ping_response.strip() == "null" or any(
            getattr(self, attr) is None for attr in ("packets_transmitted", "packets_received", "packet_loss", "packet_errors")
        )

# Global dictionary to track semaphores per endpoint host
host_locks: dict[str, threading.Semaphore] = {}

# Global lock to protect shared endpoint metrics.
endpoints_lock = threading.Lock()

# Create a mapping of endpoint URL to its EndpointInfo instance.
endpoints_info: Dict[str, EndpointInfo] = {
    "https://steakovercooked.com/api/ping/":    EndpointInfo("https://steakovercooked.com/api/ping/"),
    "https://helloacm.com/api/ping/":           EndpointInfo("https://helloacm.com/api/ping/"),
    "https://uploadbeta.com/api/ping/":         EndpointInfo("https://uploadbeta.com/api/ping/"),
    "https://happyukgo.com/api/ping/":          EndpointInfo("https://happyukgo.com/api/ping/"),
    "https://isvbscriptdead.com/api/ping/":     EndpointInfo("https://isvbscriptdead.com/api/ping/"),
    "https://api.justyy.workers.dev/api/ping/": EndpointInfo("https://api.justyy.workers.dev/api/ping/"),
}

def get_host_semaphore(url: str):
    """
    Returns a semaphore for the given endpoint host, ensuring at most 10 concurrent requests.
    """
    hostname = urlparse(url).netloc
    with endpoints_lock:
        if hostname not in host_locks:
            host_locks[hostname] = threading.Semaphore(10)
        return host_locks[hostname]

def get_sorted_endpoints():
    now = time.monotonic()

    with endpoints_lock:
        # Only consider endpoints not in cooldown first.
        available = [info for info in endpoints_info.values() if now >= info.cooldown_until]
        if available:
            return sorted(available, key=lambda info: info.score(now))
        else:
            # If all are cooling down, sort all.
            return sorted(endpoints_info.values(), key=lambda info: info.score(now))

def parse_ping_response(ping_response: str):
    # Extract individual ping times
    ping_times = [float(match.group("TIME_MS")) for match in RE_BYTES_PATTERN.finditer(ping_response)]

    # Extract packet statistics
    packets_transmitted = packets_received = packet_loss = packet_errors = None
    packets_match = RE_PACKET_STATS_PATTERN.search(ping_response)
    if packets_match:
        packets_transmitted = int(  packets_match.group("PACKETS_TRANSMITTED"))
        packets_received    = int(  packets_match.group("PACKETS_RECEIVED"))
        packet_loss         = float(packets_match.group("PACKET_LOSS_PERCENTAGE"))
        packet_errors       = int(  packets_match.group("ERRORS") or 0)

    # Extract RTT statistics
    rtt_min = rtt_avg = rtt_max = rtt_mdev = None
    rtt_match = RE_RTT_STATS_PATTERN.search(ping_response)
    if rtt_match:
        rtt_min  = float(rtt_match.group("RTT_MIN"))
        rtt_avg  = float(rtt_match.group("RTT_AVG"))
        rtt_max  = float(rtt_match.group("RTT_MAX"))
        rtt_mdev = float(rtt_match.group("RTT_MDEV"))

    return PingResult(
        ping_times=ping_times,
        packets_transmitted=packets_transmitted,
        packets_received=packets_received,
        packet_loss=packet_loss,
        packet_errors=packet_errors,
        rtt_min=rtt_min,
        rtt_avg=rtt_avg,
        rtt_max=rtt_max,
        rtt_mdev=rtt_mdev
    )

def fetch_and_parse_ping(ip: str):
    """
    Attempts to fetch and parse ping data for the given ip using the available endpoints.
    Limits to 10 concurrent requests per ip but prioritizes trying other available endpoints before waiting.
    """
    DEFAULT_COOLDOWN = 3.0

    for _ in range(len(endpoints_info)):  # Try all available endpoints
        time.sleep(0.1)

        for endpoint_info in get_sorted_endpoints():
            time.sleep(0.1)

            if ip in endpoint_info.failed_ips and endpoint_info.failed_ips[ip] >= 3:
                continue  # Skip this endpoint for this ip

            if time.monotonic() < endpoint_info.cooldown_until:
                now = time.monotonic()
                continue  # Skip if still in cooldown

            semaphore = get_host_semaphore(endpoint_info.url)

            if not semaphore.acquire(blocking=False):
                continue  # Skip this endpoint host if already at the 10-request limit

            try:
                start = time.monotonic()
                response = s.get(f"{endpoint_info.url}?host={ip}", timeout=30)
                response.raise_for_status()
                if not isinstance(response.content, bytes):
                    raise TypeError(f'Expected "bytes", got "{type(response.content).__name__}"')

                decoded_text = response.content.decode("utf-8")
                unescaped_text = decoded_text.replace("\\/", "/")

                ping_result = parse_ping_response(unescaped_text)
                if ping_result.is_invalid(unescaped_text):
                    raise InvalidPingResult(ip, unescaped_text, ping_result)

                duration = time.monotonic() - start

                with endpoints_lock:
                    endpoint_info.update_success(duration, ip)

                return ping_result

            except exceptions.RequestException as e:
                duration = time.monotonic() - start
                cooldown = DEFAULT_COOLDOWN
                if e.response is not None and (retry_after := e.response.headers.get("Retry-After")):
                    cooldown = float(retry_after)

                with endpoints_lock:
                    endpoint_info.update_failure(duration, cooldown, ip)

            finally:
                semaphore.release()  # Release slot after request

    raise AllEndpointsExhausted