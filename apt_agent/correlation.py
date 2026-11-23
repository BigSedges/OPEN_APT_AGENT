from typing import Iterable, Protocol, Sequence

from .models import Case, Event, Finding


class Correlator(Protocol):
    """Group findings into cases and resolve their event references."""

    def correlate(self, findings: Sequence[Finding], events: Sequence[Event]) -> Iterable[Case]: ...
