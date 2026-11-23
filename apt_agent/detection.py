from typing import Iterable, Protocol, Sequence

from .models import Event, Finding


class Detector(Protocol):
    """Emit evidence-backed findings from a batch of normalized events.

    Rule-based and statistical detectors implement the same contract.
    """

    def detect(self, events: Sequence[Event]) -> Iterable[Finding]: ...
