"""RDR2 process detection and immutable state snapshot.

Detects the currently running Red Dead Redemption 2 process (`RDR2.exe`),
verifies its Authenticode signature to reject impostor executables that merely
reuse the process name, and exposes the result as an immutable `RDR2Status` snapshot.
"""

from dataclasses import dataclass

from session_sniffer.capture.process import (
    GameProcessStatus,
    ProcessInfo,
    find_running_game_process,
)

_RDR2_PROCESS_NAMES: frozenset[str] = frozenset(
    {
        'rdr2.exe',
    },
)


@dataclass(frozen=True, slots=True)
class RDR2Status(GameProcessStatus):
    """Immutable snapshot of the running RDR2 process state."""


def find_running_rdr2_path(
    cached_proc: ProcessInfo | None = None,
    cached_status: RDR2Status | None = None,
) -> tuple[RDR2Status, ProcessInfo | None]:
    """Return an `RDR2Status` snapshot for the currently running RDR2 process plus its process handle."""
    return find_running_game_process(
        _RDR2_PROCESS_NAMES,
        'RDR2',
        RDR2Status,
        cached_proc=cached_proc,
        cached_status=cached_status,
    )
