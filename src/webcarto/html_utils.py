from typing import Any, Dict, List, Set
from urllib.parse import urljoin
from .urls_utils import _normalize_url

try:  # pragma: no cover
    from bs4 import BeautifulSoup  # type: ignore
except Exception:  # pragma: no cover
    BeautifulSoup = None  # type: ignore


def extract_links(html: str, base_url: str = "") -> Set[str]:
    """Versão compatível: retorna um Set de URLs normalizadas (ordem não garantida)."""
    return set(extract_links_ordered(html, base_url))


def extract_links_ordered(html: str, base_url: str = "") -> List[str]:
    """Extrai apenas links de <a href> em ordem de DOM, com deduplicação estável."""
    data = extract_links_extended(html, base_url, include_assets=False, include_forms=False)
    return data["links_a"]


def extract_links_extended(
    html: str,
    base_url: str = "",
    *,
    include_assets: bool = False,
    include_forms: bool = False,
) -> Dict[str, Any]:
    """Extrai URLs de âncoras, assets e formulários.

    Retorna dict com:
      - links_a: list[str]
      - links_assets: list[str]
      - links_forms: list[str]
      - ordered_all: list[str] (união estável conforme flags)
    """
    if BeautifulSoup is None:
        raise RuntimeError("'beautifulsoup4' is not installed. Run: pip install -r requirements.txt")
    parser = "lxml"
    try:
        import lxml  # type: ignore  # noqa: F401
    except Exception:
        parser = "html.parser"
    soup = BeautifulSoup(html, parser)

    def push(url: str, seen: Set[str], out: List[str]) -> None:
        u = _normalize_url(url)
        if u and u not in seen:
            seen.add(u)
            out.append(u)

    seen_all: Set[str] = set()
    links_a: List[str] = []
    links_assets: List[str] = []
    links_forms: List[str] = []

    # 1) <a href>
    for a in soup.find_all("a"):
        href = a.get("href")
        if not href:
            continue
        href = href.strip()
        if href.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue
        push(urljoin(base_url, href), seen_all, links_a)

    # 2) assets opcionais
    if include_assets:
        # <img src>
        for img in soup.find_all("img"):
            src = (img.get("src") or "").strip()
            if src:
                push(urljoin(base_url, src), seen_all, links_assets)
        # <script src>
        for sc in soup.find_all("script"):
            src = (sc.get("src") or "").strip()
            if src:
                push(urljoin(base_url, src), seen_all, links_assets)
        # <link href> com rel relevante
        REL_OK = {"stylesheet", "preload", "icon", "shortcut icon"}
        for lk in soup.find_all("link"):
            href = (lk.get("href") or "").strip()
            if not href:
                continue
            rel = (" ".join(lk.get("rel", [])).lower() if lk.get("rel") else (lk.get("rel") or "")).strip()
            if not rel:
                # alguns navegadores omitem; ainda pode ser asset
                pass
            # considera se intersecta com REL_OK
            if rel:
                rel_parts = {p.strip() for p in rel.split() if p.strip()}
                if REL_OK.isdisjoint(rel_parts):
                    # não é claramente asset útil
                    continue
            push(urljoin(base_url, href), seen_all, links_assets)

    # 3) formulários opcionais
    if include_forms:
        for form in soup.find_all("form"):
            action = (form.get("action") or "").strip()
            if action:
                push(urljoin(base_url, action), seen_all, links_forms)

    # União estável conforme flags: sempre primeiro anchors, depois assets, depois forms
    ordered_all: List[str] = []
    ordered_all.extend(links_a)
    if include_assets:
        ordered_all.extend(links_assets)
    if include_forms:
        ordered_all.extend(links_forms)

    return {
        "links_a": links_a,
        "links_assets": links_assets,
        "links_forms": links_forms,
        "ordered_all": ordered_all,
    }
