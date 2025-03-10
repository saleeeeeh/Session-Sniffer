# Standard Python Libraries
import subprocess


def is_npcap_installed():
    return subprocess.run(["sc", "query", "npcap"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
