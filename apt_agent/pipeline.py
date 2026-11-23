from pathlib import Path
from typing import Protocol, Sequence

from .config import PipelineConfig
from .analysis import Analyzer
from .correlation import Correlator
from .detection import Detector
from .parsing import LogParser
from .retrieval import KnowledgeIndex


class Pipeline(Protocol):
    """Orchestrate parsing, detection, correlation, retrieval, and analysis."""

    def run(
        self,
        sources: Sequence[Path],
        *,
        parser: LogParser,
        detectors: Sequence[Detector],
        correlator: Correlator,
        index: KnowledgeIndex,
        analyzer: Analyzer,
        config: PipelineConfig,
    ) -> Sequence[str]: ...
