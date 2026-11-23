from dataclasses import dataclass


@dataclass(frozen=True)
class PipelineConfig:
    """Initial settings for future correlation and retrieval implementations."""

    correlation_window_seconds: int = 900
    retrieval_top_k: int = 3
