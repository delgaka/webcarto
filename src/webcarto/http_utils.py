from typing import Optional, Any, Dict
from urllib.parse import urlparse, urlunparse
import urllib.robotparser as robotparser
import time

try:  # pragma: no cover
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None  # type: ignore

try:  # pragma: no cover
    from requests.adapters import HTTPAdapter  # type: ignore
except Exception:  # pragma: no cover
    HTTPAdapter = None  # type: ignore

try:  # pragma: no cover
    from urllib3.util.retry import Retry  # type: ignore
except Exception:  # pragma: no cover
    Retry = None  # type: ignore


def create_session(*, retries: int = 2, backoff_factor: float = 0.3, pool_maxsize: int = 10):
    """Cria uma requests.Session com HTTPAdapter configurado para retry/backoff.

    - retries: total de tentativas por requisição (inclui a primeira).
    - backoff_factor: fator exponencial para esperas (0.3, 0.6, 1.2, ...).
    - pool_maxsize: tamanho do pool de conexões no adapter.
    """
    if requests is None:
        raise RuntimeError("'requests' is not installed. Run: pip install -r requirements.txt")
    sess = requests.Session()  # type: ignore[attr-defined]
    adapter: Any
    if HTTPAdapter is not None and Retry is not None:
        retry = Retry(
            total=max(0, int(retries)),
            read=max(0, int(retries)),
            connect=max(0, int(retries)),
            backoff_factor=float(backoff_factor),
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=(
                "HEAD",
                "GET",
                "OPTIONS",
            ),
            raise_on_status=False,
            respect_retry_after_header=True,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=int(pool_maxsize))  # type: ignore[arg-type]
    else:
        # Fallback sem retry explícito
        adapter = HTTPAdapter() if HTTPAdapter is not None else None  # type: ignore
    if adapter is not None:
        sess.mount("http://", adapter)
        sess.mount("https://", adapter)
    return sess


def fetch_page(session, url: str, *, headers: Dict[str, str], timeout: int) -> tuple[Optional[Any], float, Optional[BaseException]]:
    """Executa session.get com temporização e retorna (resp, elapsed_ms, exc)."""
    if requests is None:
        raise RuntimeError("'requests' is not installed. Run: pip install -r requirements.txt")
    t0 = time.perf_counter()
    try:
        resp = session.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return resp, elapsed_ms, None
    except Exception as e:  # noqa: BLE001
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        return None, elapsed_ms, e


def is_html_response(resp) -> bool:
    """Checa se a resposta HTTP parece conter HTML (Content-Type)."""
    ctype = (resp.headers.get("Content-Type") or "").lower()
    return "html" in ctype


def load_robots(base_url: str, user_agent: str) -> robotparser.RobotFileParser:
    """Carrega/parsa robots.txt do site base. Em falha, assume permissivo."""
    rp = robotparser.RobotFileParser()
    parsed = urlparse(base_url)
    robots_url = urlunparse((parsed.scheme, parsed.netloc, "/robots.txt", "", "", ""))
    try:
        rp.set_url(robots_url)
        rp.read()
    except Exception:
        rp = robotparser.RobotFileParser()
        rp.parse(":*\nAllow: /\n".splitlines())
    return rp
