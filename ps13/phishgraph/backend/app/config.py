"""Central configuration. Every value comes from the environment (or .env); nothing secret is hard-coded."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]  # phishgraph/


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=str(ROOT / '.env'), env_file_encoding='utf-8', extra='ignore')

    # --- storage (each has a zero-dependency local fallback) ---
    database_url: str = f"sqlite:///{ROOT / 'data' / 'phishgraph.db'}"
    redis_url: str = ''  # empty -> in-process cache/queue
    neo4j_uri: str = ''  # empty -> NetworkX graph persisted to GRAPH_PATH
    graph_path: str = ''  # default data/graph.json
    neo4j_user: str = 'neo4j'
    neo4j_password: str = ''

    # --- security ---
    api_keys: str = 'dev-local-key'  # comma-separated; clients send X-API-Key
    rate_limit_per_minute: int = 600
    allow_private_targets: bool = False  # SSRF guard; only for controlled test labs
    cors_origins: str = 'http://localhost:5173,http://localhost:8000'

    # --- external threat intelligence (all optional) ---
    enable_external_ti: bool = False
    virustotal_api_key: str = ''
    urlscan_api_key: str = ''
    urlscan_submit: bool = False  # search history only unless explicitly enabled
    urlscan_visibility: str = 'private'
    abuseipdb_api_key: str = ''
    otx_api_key: str = ''
    google_safe_browsing_api_key: str = ''
    urlhaus_auth_key: str = ''
    phishtank_app_key: str = ''
    enable_active_enrichment: bool = True  # DNS / RDAP / TLS / ASN (public, no key)
    ti_timeout_s: float = 6.0

    # --- live mailboxes (explicit opt-in) ---
    enable_live_email: bool = False
    microsoft_client_id: str = ''
    microsoft_client_secret: str = ''
    microsoft_tenant_id: str = ''
    microsoft_mailbox: str = ''
    google_client_id: str = ''
    google_client_secret: str = ''
    google_refresh_token: str = ''
    imap_host: str = ''
    imap_user: str = ''
    imap_password: str = ''
    response_live_actions: bool = False  # never touch real mail unless set

    # --- behaviour ---
    demo_mode: bool = True
    feed_refresh_minutes: int = 30
    worker_concurrency: int = 8
    embedding_model: str = str(ROOT / 'models' / 'all-MiniLM-L6-v2')
    enable_embeddings: bool = True
    tranco_protect_top: int = 10000  # domains protected against look-alikes
    tranco_established_top: int = 100000  # domains never flagged as look-alikes themselves

    # --- fusion weights & thresholds (configurable, renormalised when a source is unavailable) ---
    w_nlp: float = 0.30
    w_url: float = 0.25
    w_ti: float = 0.20
    w_graph: float = 0.15
    w_brand: float = 0.05
    w_meta: float = 0.05
    t_flag: int = 30
    t_quarantine: int = 60
    t_block: int = 85

    reference_dir: str = ''  # where top-1m.csv / public_suffix_list.dat / confusables.txt live (default data/raw, then data/reference)

    @property
    def ref_dir(self) -> Path:
        if self.reference_dir:
            return Path(self.reference_dir)
        raw = ROOT / 'data' / 'raw'
        return raw if (raw / 'confusables.txt').exists() else ROOT / 'data' / 'reference'

    @property
    def data_dir(self) -> Path:
        return ROOT / 'data'

    @property
    def models_dir(self) -> Path:
        return ROOT / 'models'

    @property
    def api_key_set(self) -> set[str]:
        return {k.strip() for k in self.api_keys.split(',') if k.strip()}


@lru_cache
def get_settings() -> Settings:
    return Settings()
