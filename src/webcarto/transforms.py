from typing import Dict, Iterable, List, Optional
from urllib.parse import urlparse
import re
from .urls_utils import _domain_of_host, _domain_of_url, _hostname_of_url, strip_www


def build_domain_tree(urls: List[str]) -> Dict[str, Dict[str, List[str]]]:
    """Agrupa URLs em uma árvore domínio -> host -> [urls].

    - Usa domínio base (eTLD+1) via PSL/fallback.
    - Mantém a ordem de inserção por host/local; ordenação para saída fica a cargo do IO.
    """
    tree: Dict[str, Dict[str, List[str]]] = {}
    for u in urls:
        host = (urlparse(u).hostname or "").lower()
        if not host:
            continue
        dom = _domain_of_host(host)
        tree.setdefault(dom, {}).setdefault(host, []).append(u)
    return tree


def filter_urls(
    urls: Iterable[str],
    *,
    include_hosts: Optional[Iterable[str]] = None,
    exclude_hosts: Optional[Iterable[str]] = None,
    exclude_ext: Optional[Iterable[str]] = None,
    include_regex: Optional[str] = None,
    exclude_regex: Optional[str] = None,
    include_subdomains: bool = True,
) -> List[str]:
    """Filtra URLs por host, extensão e regex, preservando ordem de entrada.

    - include_hosts: mantém apenas URLs cujo host combine (opcional). Se include_subdomains=True,
      aceita subdomínios também.
    - exclude_hosts: remove URLs por host (mesma regra de subdomínio).
    - exclude_ext: extensões (sem ponto) a remover, comparando pelo final do caminho (case-insensitive).
    - include_regex: mantém apenas URLs que casem com a regex (aplicada na URL completa).
    - exclude_regex: remove URLs que casem com a regex.
    - include_subdomains: afeta comparação de hosts nas listas include/exclude.
    """
    inc_hosts = {strip_www(h.lower()) for h in include_hosts} if include_hosts else None
    exc_hosts = {strip_www(h.lower()) for h in exclude_hosts} if exclude_hosts else set()
    exc_ext = {e.lower().lstrip('.') for e in exclude_ext} if exclude_ext else set()
    inc_rx = re.compile(include_regex) if isinstance(include_regex, str) else None
    exc_rx = re.compile(exclude_regex) if isinstance(exclude_regex, str) else None

    def host_matches(h: str, targets: Iterable[str]) -> bool:
        h0 = strip_www(h)
        for t in targets:
            if h0 == t:
                return True
            if include_subdomains and (h0.endswith('.' + t) or t.endswith('.' + h0)):
                return True
        return False

    def path_ext(u: str) -> Optional[str]:
        p = urlparse(u).path or ''
        seg = p.rsplit('/', 1)[-1]
        if '.' in seg:
            return seg.rsplit('.', 1)[-1].lower()
        return None

    out: List[str] = []
    for u in urls:
        # include_regex
        if inc_rx is not None and not inc_rx.search(u):
            continue
        # exclude_regex
        if exc_rx is not None and exc_rx.search(u):
            continue
        # hosts include/exclude
        h = (_hostname_of_url(u) or '').lower()
        if exc_hosts and h and host_matches(h, exc_hosts):
            continue
        if inc_hosts is not None:
            if not h or not host_matches(h, inc_hosts):
                continue
        # extensions
        if exc_ext:
            ext = path_ext(u)
            if ext and ext in exc_ext:
                continue
        out.append(u)
    return out


def summarize_by_page(grouped: Dict[str, List[str]]) -> Dict[str, Dict[str, int]]:
    """Resumo simples por página: total, unique_hosts, unique_domains.

    - grouped: dict[page -> list[str]]
    - retorno: dict[page -> {total, unique_hosts, unique_domains}]
    """
    summary: Dict[str, Dict[str, int]] = {}
    for page, urls in grouped.items():
        hosts = {_hostname_of_url(u) for u in urls if u}
        domains = {_domain_of_url(u) for u in urls if u}
        summary[page] = {
            'total': len(urls),
            'unique_hosts': len({h for h in hosts if h}),
            'unique_domains': len({d for d in domains if d}),
        }
    return summary
