# Standard Python Libraries
import sys
import time
import argparse
import requests
import ipaddress
import statistics
from enum import Enum
from pathlib import Path
from typing import Union, Literal

# External/Third-party Python Libraries
from rich.table import Table
from rich import print


PingCheckResults = dict[str, list[
    Union[
        list[list[Union[str, float]]],
        list[None, dict[Literal["message"], str]]
    ]
]]

CHECK_HOST_API = "https://check-host.net"


class Colors(Enum):
    """Hex color codes for Rich formatting."""

    CYAN = "3a96dd"
    CYAN_LIGHT = "61d6d6"
    GREEN = "13a10e"
    GREEN_LIGHT = "00ff00"
    YELLOW = "c19c00"
    YELLOW_LIGHT = "f9f1a5"
    ORANGE = "ff5f00"
    ORANGE_LIGHT = "ff8700"
    RED = "c50f1f"
    RED_LIGHT = "e74856"

    def __str__(self):
        """Automatically returns the color with a '#' prefix."""
        return f"#{self.value}"


def ping_loop(target_ip: str):
    """ Continuously pings the target IP until the user closes the script. """

    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:135.0) Gecko/20100101 Firefox/135.0",
        "Accept": "application/json"
    })
    #s.verify = False

    def send_ping_request(ip: str):
        """ Sends a ping request to the Check-Host API. """
        response = s.get(f"{CHECK_HOST_API}/check-ping?host={ip}", headers={"Accept": "application/json"})
        response.raise_for_status()

        nodes = response.json()
        if not isinstance(nodes, dict):
            raise TypeError(f'Expected "dict", got "{type(nodes).__name__}"')
        request_id = nodes.get("request_id")
        if request_id is None:
            return None, None
        if not isinstance(request_id, str):
            raise TypeError(f'Expected "NoneType", got "{type(request_id).__name__}"')
        return request_id, nodes

    def get_ping_results(request_id: str, retries: int = 1, delay: int = 10):
        """Fetches the results using the request ID with retries."""
        for i in range(delay, 0, -1):
            print(f"[{Colors.CYAN}]Waiting [{Colors.CYAN_LIGHT}]{i}[/{Colors.CYAN_LIGHT}] second{pluralize(i)} for ping request to complete...  ", end="\r")
            time.sleep(1)
        print(" " * 50, end="\r")

        response = s.get(f"{CHECK_HOST_API}/check-result/{request_id}", headers={"Accept": "application/json"})
        response.raise_for_status()

        results: PingCheckResults = response.json()
        if not isinstance(results, dict):
            raise TypeError(f'Expected "dict", got "{type(results).__name__}"')

        for node, pings in results.items():
            if pings is None:
                continue

            if not isinstance(pings, list):
                raise TypeError(f'Expected "list", got "{type(pings).__name__}"')

        return results

    def pluralize(variable: int):
        return "s" if variable > 1 else ""

    def get_rtt_gradient_color(val: int):
        val = min(max(val, 0), 3000) * 0xFF // 3000
        return f"#{val:02X}{(0xFF - val):02X}00"

    def color_ping_result(successful_pings: int):
        """Returns a color-coded string based on successful pings."""
        if successful_pings == 4:
            return f"[{Colors.GREEN}]{successful_pings}[/{Colors.GREEN}]"
        elif successful_pings == 3:
            return f"[{Colors.YELLOW}]{successful_pings}[/{Colors.YELLOW}]"
        elif successful_pings == 2:
            return f"[{Colors.ORANGE}]{successful_pings}[/{Colors.ORANGE}]"
        elif successful_pings == 1:
            return f"[{Colors.RED}]{successful_pings}[/{Colors.RED}]"
        else:
            return f"[{Colors.RED}]{successful_pings}[/{Colors.RED}]"

    while True:
        request_id, nodes = send_ping_request(target_ip)

        if not request_id or not nodes:
            print(f"[{Colors.RED}]Failed to send ping request to [{Colors.RED_LIGHT}]{target_ip}[/{Colors.RED_LIGHT}].[/{Colors.RED}]")

            for i in range(100, 0, -1):
                print(f"[{Colors.YELLOW}]Retrying in [{Colors.YELLOW_LIGHT}]{i}[/{Colors.YELLOW_LIGHT}] second{pluralize(i)}...[/{Colors.YELLOW}]   ", end="\r")
                time.sleep(1)

            print("\n")
            continue

        print(f"[{Colors.CYAN}]Ping request sent to [{Colors.CYAN_LIGHT}]{target_ip}[/{Colors.CYAN_LIGHT}]. Result API link: [link={CHECK_HOST_API}/check-result/{request_id}][{Colors.CYAN_LIGHT} bold]{CHECK_HOST_API}/check-result/{request_id}[/{Colors.CYAN_LIGHT} bold][/link][/{Colors.CYAN}]")

        results: PingCheckResults = get_ping_results(request_id)
        if not isinstance(results, dict):
            raise TypeError(f'Expected "dict", got "{type(results).__name__}"')
        if not results:
            print(f"[{Colors.RED}]Failed to retrieve ping results.[/{Colors.RED}]")
            time.sleep(10)
            continue

        global_rtt_values: list[float | int] = []

        table = Table(title=f"[{Colors.CYAN}]Ping Results from[/{Colors.CYAN}] [{Colors.CYAN_LIGHT}]{target_ip}[/{Colors.CYAN_LIGHT}]", show_header=True, header_style=f"bold {Colors.CYAN_LIGHT}")
        table.add_column("Country",      header_style=f"{Colors.CYAN_LIGHT}")
        table.add_column("City",         header_style=f"{Colors.CYAN_LIGHT}")
        table.add_column("Success",      header_style=f"bold {Colors.CYAN_LIGHT}", justify="center")
        table.add_column("Min RTT (ms)", header_style=f"{Colors.GREEN}", justify="right")
        table.add_column("Avg RTT (ms)", header_style=f"{Colors.YELLOW}", justify="right")
        table.add_column("Max RTT (ms)", header_style=f"{Colors.RED}", justify="right")

        for node, pings in results.items():
            country = nodes["nodes"][node][1]
            if not isinstance(country, str):
                raise TypeError(f'Expected "str", got "{type(country).__name__}"')
            city = nodes["nodes"][node][2]
            if not isinstance(city, str):
                raise TypeError(f'Expected "str", got "{type(city).__name__}"')

            message = None
            if pings is None:
                message = "Inactivity timeout"
            elif pings[0] is None:  # and len(pings) == 2  # and isinstance(pings[1], dict) and pings[1].get("message"):  # in ("Connect timeout", "No route to host")
                message = pings[1]["message"]

            this_rtt_values: list[float | int] = []

            successful_pings = 0

            if message is None:
                for ping in pings:
                    for i in range(4):
                        result = ping[i][0]
                        if not isinstance(result, str):
                            raise TypeError(f'Expected "str", got "{type(result).__name__}"')
                        rtt = ping[i][1]
                        if not isinstance(rtt, (float, int)):
                            raise TypeError(f'Expected "(float, int)", got "{type(rtt).__name__}"')

                        if result == "OK":
                            successful_pings += 1

                        this_rtt_values.append(rtt)
                        global_rtt_values.append(rtt)

            rows = [
                country,
                city,
                f"{color_ping_result(successful_pings)}/[{Colors.GREEN}]4[/{Colors.GREEN}]"
            ]

            if this_rtt_values:
                rtt_min = min(this_rtt_values) * 1000
                rtt_avg = statistics.mean(this_rtt_values) * 1000
                rtt_max = max(this_rtt_values) * 1000
                rtt_min_color = get_rtt_gradient_color(round(rtt_min))
                rtt_avg_color = get_rtt_gradient_color(round(rtt_avg))
                rtt_max_color = get_rtt_gradient_color(round(rtt_max))
                rows.extend([
                    f"[{rtt_min_color}]{round(rtt_min, 1)}[/{rtt_min_color}] ms",
                    f"[{rtt_avg_color}]{round(rtt_avg, 1)}[/{rtt_avg_color}] ms",
                    f"[{rtt_max_color}]{round(rtt_max, 1)}[/{rtt_max_color}] ms"
                ])
            else:
                rows.extend([
                    f"[{Colors.RED}]{message}[/{Colors.RED}]",
                    f"[{Colors.RED}]{message}[/{Colors.RED}]",
                    f"[{Colors.RED}]{message}[/{Colors.RED}]"
                ])

            table.add_row(*rows)

        print()
        print(table)

        if global_rtt_values:
            global_rtt_min = min(global_rtt_values) * 1000
            global_rtt_avg = statistics.mean(global_rtt_values) * 1000
            global_rtt_max = max(global_rtt_values) * 1000
            global_rtt_min_color = get_rtt_gradient_color(round(global_rtt_min))
            global_rtt_avg_color = get_rtt_gradient_color(round(global_rtt_avg))
            global_rtt_max_color = get_rtt_gradient_color(round(global_rtt_max))

            print("\n[cyan]RTT Statistics [cyan]([/cyan]All Nodes Combined[cyan])[/cyan]:[/cyan]")
            print(f"[{Colors.GREEN}]Min RTT:[/{Colors.GREEN}] [{global_rtt_min_color}]{str(round(global_rtt_min, 1)).ljust(6)}[/{global_rtt_min_color}] ms")
            print(f"[{Colors.YELLOW}]Avg RTT:[/{Colors.YELLOW}] [{global_rtt_avg_color}]{str(round(global_rtt_avg, 1)).ljust(6)}[/{global_rtt_avg_color}] ms")
            print(f"[{Colors.RED}]Max RTT:[/{Colors.RED}] [{global_rtt_max_color}]{str(round(global_rtt_max, 1)).ljust(6)}[/{global_rtt_max_color}] ms")
        else:
            print(f"\n[{Colors.RED}]No RTT data available.[/{Colors.RED}]")

        print()
        print(f"[bold {Colors.YELLOW_LIGHT}]- [/bold {Colors.YELLOW_LIGHT}]" * 22)
        print()

        for i in range(20, 0, -1):
            print(f"[{Colors.CYAN}]Waiting [{Colors.CYAN_LIGHT}]{i}[/{Colors.CYAN_LIGHT}] second{pluralize(i)} before the next ping request...[/{Colors.CYAN}]  ", end="\r")
            time.sleep(1)
        print(" " * 50, end="\r")

def main():
    parser = argparse.ArgumentParser(description="Ping an IP using Check-Host API.")
    parser.add_argument("ip", metavar='<ip>', type=str, help="Target IP to ping")
    args = parser.parse_args()

    target_ip = args.ip.strip() if isinstance(args.ip, str) else None
    if not target_ip:
        print(f"[{Colors.RED}]Error: No IP address provided.[/{Colors.RED}]")
        exit(1)

    try:
        ipaddress.ip_address(target_ip)
    except ValueError:
        print(f"[{Colors.RED}]Error: '{Colors.RED_LIGHT}{target_ip}{Colors.RED_LIGHT}' is not a valid IP address.[/{Colors.RED}]")
        exit(1)

    try:
        ping_loop(target_ip)
    except KeyboardInterrupt:
        exit(0)

if __name__ == "__main__":
    main()
