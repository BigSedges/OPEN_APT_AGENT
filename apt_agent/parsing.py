from pathlib import Path
from typing import Iterable, Protocol

from .models import Event


class LogParser(Protocol):
    """Convert one log source to normalized events."""

    def parse(self, source: Path) -> Iterable[Event]: ...
