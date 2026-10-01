"""Reusable debounced filesystem watcher for auto-refreshing GUI views from disk."""

from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import QFileSystemWatcher, QObject, QTimer

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable


class DebouncedFileWatcher(QObject):
    """Watch files and/or directories and invoke a callback (debounced) when they change.

    Editors and log writers often replace files atomically (write temp, delete, rename),
    which drops the path from a raw `QFileSystemWatcher`.  This wrapper re-arms the watched
    paths on every notification, coalesces rapid bursts through a single-shot timer, and then
    calls the supplied callback once the dust settles.
    """

    def __init__(self, parent: QObject | None, on_change: Callable[[], None], *, interval_ms: int = 250) -> None:
        """Create a watcher that calls *on_change* at most once per *interval_ms* burst."""
        super().__init__(parent)
        self._on_change = on_change
        self._files: list[str] = []
        self._directories: list[str] = []

        self._watcher = QFileSystemWatcher(self)
        self._watcher.fileChanged.connect(self._schedule)
        self._watcher.directoryChanged.connect(self._schedule)

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(interval_ms)
        self._timer.timeout.connect(self._fire)

    def watch(self, *, files: Iterable[Path] = (), directories: Iterable[Path] = ()) -> None:
        """Replace the set of watched *files* and *directories* and arm the watcher."""
        self.stop()
        self._files = [str(file) for file in files]
        self._directories = [str(directory) for directory in directories]
        self._rearm()

    def stop(self) -> None:
        """Stop the debounce timer and clear all watched paths."""
        self._timer.stop()
        watched = [*self._watcher.files(), *self._watcher.directories()]
        if watched:
            self._watcher.removePaths(watched)

    def _rearm(self) -> None:
        """Re-establish watched paths, only adding paths that are missing and exist."""
        watched_files = set(self._watcher.files())
        watched_dirs = set(self._watcher.directories())
        paths_to_add = [path_str for path_str in self._files if path_str not in watched_files and Path(path_str).exists()]
        paths_to_add.extend(dir_str for dir_str in self._directories if dir_str not in watched_dirs and Path(dir_str).exists())

        if paths_to_add:
            self._watcher.addPaths(paths_to_add)

    def _schedule(self, _path: str) -> None:
        """Coalesce a filesystem notification into the pending debounce window."""
        self._timer.start()

    def _fire(self) -> None:
        """Re-arm the watch list, then notify the consumer of the settled change."""
        self._rearm()
        self._on_change()
