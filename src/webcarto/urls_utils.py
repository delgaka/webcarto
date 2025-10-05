from typing import List, Tuple, Optional, Dict, Any
from urllib.parse import urlparse, urlunparse
from pathlib import Path
import datetime

try:  # pragma: no cover
    import tldextract  # type: ignore
except Exception:  # pragma: no cover
    tldextract = None  # type: ignore

_tldx_cached = None  # cache do extrator configurado


def strip_www(h: str) -> str:
    return h[4:] if h.startswith("www.") else h


def group_links_by_host(links: List[str], base_host: str, include_subdomains: bool) -> Tuple[List[str], List[str], List[str]]:
    """Classifica links em três grupos para ordenação determinística.

    Retorna (same_host, subdomains, externals).
    """
    same_host_group: List[str] = []
    subdomain_group: List[str] = []
    external_group: List[str] = []
    for link in links:
        lh = (urlparse(link).hostname or "").lower()
        lh_s = strip_www(lh)
        if lh_s == base_host:
            same_host_group.append(link)
        elif (not include_subdomains) and lh_s != base_host:
            external_group.append(link)
        elif include_subdomains and (lh_s.endswith("." + base_host) or base_host.endswith("." + lh_s)):
            subdomain_group.append(link)
        else:
            external_group.append(link)
    return same_host_group, subdomain_group, external_group


def _get_tldx():
    """Obtém um extrator tldextract com cache local e atualização diária.

    Estratégia:
    - Cache local em `.tldcache/` ao lado deste arquivo.
    - Uma vez por dia, tenta atualizar a PSL (rede permitida). Em falha, usa cache existente.
    - Sem cache/rede, cai no snapshot embutido (modo offline).
    """
    global _tldx_cached
    if _tldx_cached is not None:
        return _tldx_cached
    if tldextract is None:
        return None

    root = Path(__file__).resolve().parent
    cache_dir = root / ".tldcache"
    marker = cache_dir / "last_refresh.txt"
    today = datetime.date.today().isoformat()
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    allow_refresh = True
    try:
        if marker.exists() and marker.read_text(encoding="utf-8").strip() == today:
            allow_refresh = False
    except Exception:
        allow_refresh = False

    if allow_refresh:
        try:
            tx = tldextract.TLDExtract(cache_dir=str(cache_dir))  # rede permitida
            _ = tx("example.com")
            try:
                marker.write_text(today, encoding="utf-8")
            except Exception:
                pass
            _tldx_cached = tx
            return _tldx_cached
        except Exception:
            pass

    try:
        tx = tldextract.TLDExtract(cache_dir=str(cache_dir), suffix_list_urls=None)
    except Exception:
        tx = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=None)
    _tldx_cached = tx
    return _tldx_cached


def _normalize_url(u: str) -> Optional[str]:
    """Normaliza uma URL para comparação/união.

    - Mantém apenas http/https; remove fragmento; normaliza scheme/host; remove
      portas padrão; normaliza barra final (exceto na raiz).
    """
    u = (u or "").strip()
    if not u:
        return None
    parsed = urlparse(u)
    if parsed.scheme not in ("http", "https"):
        return None
    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower() if parsed.hostname else ""
    port = parsed.port
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        netloc = host
    elif port:
        netloc = f"{host}:{port}"
    else:
        netloc = host
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    normalized = urlunparse((scheme, netloc, path, "", parsed.query, ""))
    return normalized


def _same_site(u: str, origin: str, *, include_subdomains: bool = True) -> bool:
    pu, po = urlparse(u), urlparse(origin)
    hu = (pu.hostname or "").lower()
    ho = (po.hostname or "").lower()
    hu, ho = strip_www(hu), strip_www(ho)
    if not hu or not ho:
        return False
    if include_subdomains:
        return hu == ho or hu.endswith("." + ho) or ho.endswith("." + hu)
    return hu == ho


def _hostname_of_url(u: str) -> str:
    return (urlparse(u).hostname or "").lower()


def _domain_of_host(host: str) -> str:
    tx = _get_tldx()
    if tx is not None:
        ext = tx(host)  # type: ignore[misc]
        reg = ext.registered_domain
        return reg or host
    SUFFIX_2LD = {
        "com.br", "net.br", "org.br", "gov.br", "edu.br", "mil.br",
        "co.uk", "org.uk", "gov.uk", "ac.uk",
        "com.au", "net.au", "org.au",
        "co.jp", "or.jp", "ne.jp",
        "com.ar", "com.mx", "com.tr",
        "com.cn", "com.hk", "com.sg", "com.sa",
        "com.co", "com.pe", "com.ec",
    }
    parts = host.split(".")
    for suf in SUFFIX_2LD:
        if host.endswith("." + suf) and len(parts) >= (len(suf.split(".")) + 1):
            k = len(suf.split("."))
            return ".".join(parts[-(k+1):])
        if host == suf:
            return host
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _domain_of_url(u: str) -> str:
    return _domain_of_host(_hostname_of_url(u))

