# External/Third-party Python Libraries
from pypresence import Presence, DiscordNotFound, PipeClosed, ResponseTimeout, exceptions

# Standard Python Libraries
import time
import queue
import threading
from typing import Union


QueueHint = queue.SimpleQueue[Union[str, None, "ShutdownSignal"]]


class ShutdownSignal(object):
    """A unique type to represent the shutdown signal."""
    pass


_SHUT_DOWN = ShutdownSignal()


class DiscordRPC:
    """Manages Discord Rich Presence updates and connection."""

    def __init__(self, client_id: int):
        self._RPC = Presence(client_id)
        self._closed = False
        self._queue: QueueHint = queue.SimpleQueue()

        self.connection_status = threading.Event()

        self._thread = threading.Thread(target=_run, args=(self._RPC, self._queue, self.connection_status))
        self._thread.start()

        self.last_update_time: float | None = None

    def update(self, state_message: str | None = None):
        """
        Attempts to update the Discord Rich Presence.

        Args:
            state_message (optional): If provided, the state message to display in Discord presence.
        """
        if self._closed:
            return

        self.last_update_time = time.monotonic()

        if self._thread.is_alive():
            self._queue.put(state_message)

    def close(self):
        """Remove the Discord Rich Presence."""
        if self._closed:
            return

        self._closed = True
        self._queue.put(_SHUT_DOWN)
        self._thread.join(timeout=3)


def _run(RPC: Presence, queue: QueueHint, connection_status: threading.Event):
    DISCORD_RPC_TITLE = "Sniffin' my babies IPs"
    START_TIME = time.time()
    DISCORD_RPC_BUTTONS = [
        {"label": "GitHub Repo", "url": "https://github.com/BUZZARDGTA/Session-Sniffer"},
    ]

    while True:
        status_message = queue.get()
        if status_message is _SHUT_DOWN:
            if connection_status.is_set():
                RPC.clear()
                RPC.close()
            return

        if not connection_status.is_set():
            try:
                RPC.connect()
            except (DiscordNotFound, exceptions.DiscordError):
                continue
            else:
                connection_status.set()

        try:
            RPC.update(
                state=status_message or None,
                details=DISCORD_RPC_TITLE,
                start=START_TIME,
                buttons=DISCORD_RPC_BUTTONS,
            )
        except (PipeClosed, ResponseTimeout):
            connection_status.clear()