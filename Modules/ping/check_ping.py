# Standard Python Libraries
import re
import sys
import time
import threading
from pathlib import Path
from requests import exceptions
from typing import Optional, NamedTuple, Dict
from dataclasses import dataclass

# Local Python Libraries (Included with Project)
parent_dir = Path(__file__).resolve().parent.parent
sys.path.append(str(parent_dir))
from Modules.https_utils.unsafe_https import s


@dataclass
class EndpointInfo:
    url: str
    calls: int = 0
    failures: int = 0
    total_time: float = 0.0
    cooldown_until: float = 0.0

    def update_success(self, duration: float):
        self.calls += 1
        self.total_time += duration

    def update_failure(self, duration: float, cooldown: float = 60.0):
        self.calls += 1
        self.failures += 1
        self.total_time += duration
        self.cooldown_until = time.monotonic() + cooldown

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
    packet_loss:         Optional[int]
    rtt_min:             Optional[float]
    rtt_avg:             Optional[float]
    rtt_max:             Optional[float]
    rtt_mdev:            Optional[float]


def parse_ping_response(response_content: bytes):
    decoded_text = response_content.decode("utf-8")
    unescaped_text = decoded_text.replace('\\/', '/')
    if unescaped_text == "null":
        return None

    # Extract individual ping times.
    ping_times = [float(t) for t in re.findall(r'time=([\d\.]+) ms', unescaped_text)]
    # Extract packet statistics.
    if packets_info := re.search(r'(\d+) packets transmitted, (\d+) received, (\d+)% packet loss', unescaped_text):
        packets_transmitted, packets_received, packet_loss = map(int, packets_info.groups())
    else:
        packets_transmitted = packets_received = packet_loss = None
    # Extract RTT statistics.
    if rtt_info := re.search(r'rtt min/avg/max/mdev = ([\d\.]+)/([\d\.]+)/([\d\.]+)/([\d\.]+) ms', unescaped_text):
        rtt_min, rtt_avg, rtt_max, rtt_mdev = map(float, rtt_info.groups())
    else:
        rtt_min = rtt_avg = rtt_max = rtt_mdev = None

    return PingResult(
        ping_times=ping_times,
        packets_transmitted=packets_transmitted,
        packets_received=packets_received,
        packet_loss=packet_loss,
        rtt_min=rtt_min,
        rtt_avg=rtt_avg,
        rtt_max=rtt_max,
        rtt_mdev=rtt_mdev
    )


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


def fetch_and_parse_ping(host: str):
    """
    Attempts to fetch and parse ping data for the given host using the available endpoints.
    Endpoints are tried sequentially in order of their computed score.
    On failure (especially with 429 errors), the endpoint is placed into cooldown.
    """
    DEFAULT_COOLDOWN = 60.0

    for endpoint_info in get_sorted_endpoints():
        # Skip if the endpoint is still cooling down.
        if time.monotonic() < endpoint_info.cooldown_until:
            continue

        start = time.monotonic()
        try:
            response = s.get(f"{endpoint_info.url}?host={host}", timeout=60)
            response.raise_for_status()
            if not isinstance(response.content, bytes):
                raise TypeError(f'Expected "bytes", got "{type(response.content).__name__}"')
            result = parse_ping_response(response.content)
            duration = time.monotonic() - start

            with endpoints_lock:
                endpoint_info.update_success(duration)

            return result

        except exceptions.RequestException as e:
            duration = time.monotonic() - start
            if e.response is not None:
                if retry_after := e.response.headers.get("Retry-After"):
                    cooldown = float(retry_after)
                else:
                    cooldown = DEFAULT_COOLDOWN

            with endpoints_lock:
                endpoint_info.update_failure(duration, cooldown=cooldown)

            #print(f"Endpoint {endpoint_info.url} failed for host {host}: {e}")
            continue