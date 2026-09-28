import os
import sys
import tempfile
from pathlib import Path

_tmp = Path(tempfile.mkdtemp(prefix='phishgraph-test-'))
os.environ.update({
    'DATABASE_URL': f'sqlite:///{_tmp / "test.db"}',
    'GRAPH_PATH': str(_tmp / 'graph.json'),
    'ENABLE_ACTIVE_ENRICHMENT': 'false',
    'ENABLE_EXTERNAL_TI': 'false',
    'ENABLE_EMBEDDINGS': os.environ.get('TEST_EMBEDDINGS', 'false'),
    'API_KEYS': 'test-key',
    'REDIS_URL': '',
    'NEO4J_URI': '',
    'RATE_LIMIT_PER_MINUTE': '100000',
})
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402

from app.database import init_db  # noqa: E402

init_db()


@pytest.fixture(scope='session')
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture
def auth():
    return {'X-API-Key': 'test-key'}
