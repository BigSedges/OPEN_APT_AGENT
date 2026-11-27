"""No API key, no private data. Run real ToolNode protocol acceptance tests."""
import os
from pathlib import Path
import sys
os.environ['LANGSMITH_TRACING'] = 'false'
os.environ['LANGCHAIN_TRACING_V2'] = 'false'
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
import pytest
if __name__ == '__main__':
    raise SystemExit(pytest.main(['-q', '-p', 'no:cacheprovider', str(root/'tests/test_screening_tools.py')]))
