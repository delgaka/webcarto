"""Analisador pós-crawl para scripts JavaScript coletados pelo WebCarto."""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

try:  # pragma: no cover
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None  # type: ignore

from .http_utils import create_session
from .urls_utils import _domain_of_url, _hostname_of_url, _normalize_url

SCHEMA = "webcarto.js-analysis#1"
JS_EXTENSIONS = {"js", "mjs"}
TOKEN_RULES: Dict[str, Tuple[str, str]] = {
    "eval(": ("exec_dynamic", "eval("),
    "function(": ("exec_dynamic", "Function("),
    "settimeout(": ("exec_dynamic", "setTimeout("),
    "setinterval(": ("exec_dynamic", "setInterval("),
    "document.write(": ("dom_injection", "document.write("),
    "atob(": ("obfuscation", "atob("),
    "xmlhttprequest": ("net_beacon", "XMLHttpRequest"),
    "fetch(": ("net_beacon", "fetch("),
    "websocket": ("net_beacon", "WebSocket"),
    "crypto.subtle": ("obfuscation", "crypto.subtle"),
    "navigator.sendbeacon": ("net_beacon", "navigator.sendBeacon"),
    "localstorage": ("storage_sensitive", "localStorage"),
    "sessionstorage": ("storage_sensitive", "sessionStorage"),
    "document.cookie": ("storage_sensitive", "document.cookie"),
}
CATEGORY_TO_OWASP: Dict[str, List[str]] = {
    "exec_dynamic": ["OWASP-A03-2021"],
    "dom_injection": ["OWASP-A03-2021", "OWASP-A05-2021"],
    "net_beacon": ["OWASP-A05-2021"],
    "obfuscation": ["OWASP-A04-2021"],
    "redirect_control": ["OWASP-A01-2021"],
    "storage_sensitive": ["OWASP-A07-2021"],
    "third_party_loader": ["OWASP-A08-2021"],
    "cross_context": ["OWASP-A01-2021", "OWASP-A08-2021"],
}
CATEGORY_TO_MITRE: Dict[str, List[str]] = {
    "exec_dynamic": ["T1059.007"],
    "dom_injection": ["T1185", "T1608"],
    "net_beacon": ["T1071"],
    "obfuscation": ["T1027"],
    "redirect_control": ["T1204", "T1185"],
    "storage_sensitive": ["T1555"],
    "third_party_loader": ["T1105", "T1608"],
    "cross_context": ["T1102"],
}
LOCATION_WRITE_RE = re.compile(r"(?:window\.)?location(?:\.(?:href|assign|replace))?\s*=")
IOC_REGEX = re.compile(r"https?://[\w\-.:/?=&%+#]+", re.IGNORECASE)
BASE64_SUSPECT = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
UNICODE_HIDDEN = re.compile(r"[\u0300-\u036f\u200b\u200c\u200d\ufeff]")


def run(argv: Optional[Iterable[str]] = None) -> int:
    """Entry point for the ``webcarto analyze-js`` subcommand."""
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if requests is None:
        parser.error("'requests' is not installed. Run: pip install -r requirements.txt")

    reputation_cache = _load_reputation(args.reputation)
    existing_analysis = _load_existing(args.output) if not args.refresh else {}

    verbose = not args.quiet

    if args.script_url:
        candidates: List[Tuple[str, Optional[str]]] = [(args.script_url, None)]
        source = args.script_url
    else:
        urls_payload = _load_json(args.urls, parser, label="URLs")
        items = urls_payload.get("items", []) if isinstance(urls_payload, dict) else []
        source = (urls_payload.get("meta") or {}).get("source") if isinstance(urls_payload, dict) else None
        candidates = _extract_script_candidates(items, include_subdomains=args.include_subdomains)
        if not candidates:
            print("[analyze-js] Nenhum script .js encontrado nas URLs fornecidas")
            _persist([], args.output, source=source, meta_extra={}, metrics={})
            return 0

    total_candidates = len(candidates)
    effective_total = min(total_candidates, args.limit) if args.limit else total_candidates
    session = create_session(retries=args.retries, backoff_factor=args.retry_backoff)
    session.headers.update({"User-Agent": "webcarto-analyze-js/1.0"})

    results: List[Dict[str, Any]] = []
    reused = 0
    processed = 0
    for seq, candidate in enumerate(candidates, start=1):
        if args.limit and processed >= effective_total:
            break
        current_index = processed + 1
        url, page = candidate
        cache_key = url
        if cache_key in existing_analysis and not args.script_url:
            record = existing_analysis[cache_key]
            print(f"[analyze-js] [{current_index}/{effective_total}] cache reutilizado -> {url}")
            results.append(record)
            reused += 1
            processed += 1
            _print_record_summary(record, verbose=verbose)
            continue
        print(f"[analyze-js] [{current_index}/{effective_total}] analisando {url}")
        try:
            record = _analyze_single(
                session,
                url,
                page=page,
                timeout=args.timeout,
                origin=source,
                reputation_cache=reputation_cache,
                verbose=verbose,
            )
            results.append(record)
            processed += 1
            _print_record_summary(record, verbose=verbose)
        except Exception as exc:  # noqa: BLE001
            if args.strict:
                raise
            error_record = {
                "url": url,
                **({"page": page} if page else {}),
                "status": None,
                "error": type(exc).__name__,
                "message": str(exc),
            }
            results.append(error_record)
            processed += 1
            _print_record_summary(error_record, verbose=True)

    metrics = _build_metrics(results)
    meta_extra = {
        "source": source,
        "total_candidates": len(candidates),
        "cache_reused": reused,
    }
    _persist(results, args.output, source=source, meta_extra=meta_extra, metrics=metrics)
    print(f"[analyze-js] Analisados {len(results)} script(s) -> {args.output}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analisa scripts JavaScript coletados previamente")
    parser.add_argument(
        "--urls",
        type=Path,
        default=Path("out/urls.json"),
        help="Arquivo JSON gerado pelo webcarto (site-scraper.urls#1)",
    )
    parser.add_argument(
        "--script-url",
        help="Analisa apenas esse script remoto específico (ignora --urls quando informado)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("out/js-analysis.json"),
        help="Arquivo de saída (JSON) com os resultados da análise",
    )
    parser.add_argument(
        "--reputation",
        type=Path,
        default=Path("out/reputation.json"),
        help="Cache opcional de reputação (produzido por --verify-reputation)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="Timeout de download por script (segundos)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="Total de tentativas HTTP por script",
    )
    parser.add_argument(
        "--retry-backoff",
        type=float,
        default=0.3,
        help="Backoff exponencial entre tentativas HTTP",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Limita a quantidade de scripts analisados",
    )
    parser.add_argument(
        "--include-subdomains",
        action="store_true",
        help="Trata subdomínios como internos ao medir ownership",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Ignora resultados previamente salvos e reanalisa todos os scripts",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Em caso de erro ao analisar um script, aborta imediatamente",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Reduz a verbosidade (por padrão a execução mostra progresso detalhado)",
    )
    return parser


def _load_json(path: Path, parser: argparse.ArgumentParser, *, label: str) -> Dict[str, Any]:
    if not path.exists():
        parser.error(f"Arquivo de {label} não encontrado: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:  # noqa: B902
        parser.error(f"Arquivo de {label} inválido ({exc})")
    except Exception as exc:  # noqa: BLE001
        parser.error(f"Não foi possível ler {path}: {exc}")
    raise RuntimeError("unreachable")


def _load_reputation(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get("items", {}) if isinstance(data, dict) else {}
    except Exception:
        return {}


def _load_existing(path: Path) -> Dict[str, Dict[str, Any]]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    items = data.get("items") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return {}
    return {entry.get("url"): entry for entry in items if isinstance(entry, dict) and entry.get("url")}


def _extract_script_candidates(items: Iterable[Dict[str, Any]], *, include_subdomains: bool) -> List[Tuple[str, Optional[str]]]:
    candidates: List[Tuple[str, Optional[str]]] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        if not isinstance(url, str):
            continue
        url_n = _normalize_url(url)
        if not url_n or url_n in seen:
            continue
        if not _looks_like_script(url_n):
            continue
        seen.add(url_n)
        page = item.get("page") if isinstance(item.get("page"), str) else None
        candidates.append((url, page))
    return candidates


def _looks_like_script(url: str) -> bool:
    parsed = urlparse(url)
    path = parsed.path.lower()
    if any(path.endswith(f".{ext}") for ext in JS_EXTENSIONS):
        return True
    if ".js" in path:
        return True
    if parsed.query and "=.js" in parsed.query.lower():
        return True
    return False


def _analyze_single(
    session,
    url: str,
    *,
    page: Optional[str],
    timeout: int,
    origin: Optional[str],
    reputation_cache: Dict[str, Any],
    verbose: bool,
) -> Dict[str, Any]:
    resp = session.get(url, timeout=timeout, allow_redirects=True)
    status = getattr(resp, "status_code", None)
    content = resp.content if getattr(resp, "content", None) else b""
    text = content.decode("utf-8", errors="ignore")
    sha256 = hashlib.sha256(content).hexdigest()
    line_count = text.count("\n") + 1 if text else 0
    size_bytes = len(content)
    entropy = _shannon_entropy(content)

    tokens_found, token_categories = _scan_tokens(text)
    potential_iocs = _extract_iocs(text)
    unicode_flags = bool(UNICODE_HIDDEN.search(text))
    obfuscation_score = _score_obfuscation(text, entropy, unicode_flags)
    host = _hostname_of_url(url) or ""
    reputation = _lookup_reputation(host, reputation_cache)
    high_signal = _is_high_signal(
        token_categories=token_categories,
        suspicious_tokens=tokens_found,
        obfuscation_score=obfuscation_score,
        potential_ioc_count=len(potential_iocs),
        unicode_flags=unicode_flags,
    )
    ownership = None
    if origin:
        try:
            ownership = "internal" if _domain_of_url(url) == _domain_of_url(origin) else "external"
        except Exception:
            ownership = None
    record: Dict[str, Any] = {
        "url": url,
        **({"page": page} if page else {}),
        "status": status,
        "size_bytes": size_bytes,
        "sha256": sha256,
        "line_count": line_count,
        "entropy": round(entropy, 3) if entropy is not None else None,
        "suspicious_tokens": sorted(tokens_found),
        "token_categories": sorted(token_categories),
        "potential_ioc_sample": potential_iocs[:5],
        "potential_ioc_count": len(potential_iocs),
        "obfuscation_score": obfuscation_score,
        "unicode_trickery": unicode_flags,
        "high_risk": high_signal,
        "ownership": ownership,
        "host": host,
    }
    owasp_refs = _collect_refs(token_categories, CATEGORY_TO_OWASP)
    if owasp_refs:
        record["owasp_refs"] = owasp_refs
    mitre_refs = _collect_refs(token_categories, CATEGORY_TO_MITRE)
    if mitre_refs:
        record["mitre_techniques"] = mitre_refs
    if reputation:
        record["reputation"] = reputation
    return record


def _scan_tokens(text: str) -> Tuple[set[str], set[str]]:
    found: set[str] = set()
    categories: set[str] = set()
    snippet = text[:200_000]
    lowered = snippet.lower()
    for needle, (category, label) in TOKEN_RULES.items():
        if needle in lowered:
            found.add(label)
            categories.add(category)
    if "import(" in lowered:
        found.add("import(")
        categories.add("third_party_loader")
    if LOCATION_WRITE_RE.search(snippet):
        found.add("location-write")
        categories.add("redirect_control")
    if "postmessage" in lowered:
        found.add("postMessage")
        categories.add("cross_context")
    return found, categories


def _extract_iocs(text: str) -> List[str]:
    urls = IOC_REGEX.findall(text)
    seen: set[str] = set()
    out: List[str] = []
    for url in urls:
        if url not in seen:
            seen.add(url)
            out.append(url)
    # possíveis strings base64 longas
    for match in BASE64_SUSPECT.findall(text):
        if match not in seen:
            seen.add(match)
            out.append(match)
    return out


def _score_obfuscation(text: str, entropy: Optional[float], unicode_flags: bool) -> int:
    if not text:
        return 0
    metrics = []
    # linhas longas / ausência de quebras
    if text and text.count("\n") <= 3:
        metrics.append(3)
    avg_line = len(text) / max(1, text.count("\n") + 1)
    if avg_line > 180:
        metrics.append(2)
    if entropy and entropy > 4.5:
        metrics.append(2)
    if BASE64_SUSPECT.search(text):
        metrics.append(2)
    if unicode_flags:
        metrics.append(2)
    return min(10, sum(metrics))


def _is_high_signal(
    *,
    token_categories: Iterable[str],
    suspicious_tokens: Iterable[str],
    obfuscation_score: Optional[int],
    potential_ioc_count: int,
    unicode_flags: bool,
) -> bool:
    categories = set(token_categories)
    tokens = set(suspicious_tokens)
    high_risk_rules = [
        categories.issuperset({"exec_dynamic", "obfuscation"}),
        categories.issuperset({"exec_dynamic", "net_beacon"}),
        categories.issuperset({"dom_injection", "obfuscation"}),
        categories.issuperset({"redirect_control", "net_beacon"}),
        categories.issuperset({"storage_sensitive", "net_beacon"}),
    ]
    obfuscation_heavy = (obfuscation_score or 0) >= 7 and unicode_flags and potential_ioc_count >= 10
    redirect_eval_combo = "location-write" in tokens and "eval(" in tokens
    return any(high_risk_rules) or obfuscation_heavy or redirect_eval_combo


def _collect_refs(categories: Iterable[str], mapping: Dict[str, List[str]]) -> List[str]:
    refs: set[str] = set()
    for cat in categories:
        refs.update(mapping.get(cat, []))
    return sorted(refs)


def _lookup_reputation(host: str, cache: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not host or host not in cache:
        return None
    providers = cache[host].get("providers") if isinstance(cache[host], dict) else None
    if not isinstance(providers, dict):
        return None
    data = {}
    for prov, info in providers.items():
        payload = None
        if isinstance(info, dict):
            payload = info.get("data") or info
        if isinstance(payload, dict):
            data[prov] = {
                k: payload.get(k)
                for k in ("verdict", "score", "categories", "source")
                if k in payload
            }
    return data or None


def _shannon_entropy(data: bytes) -> Optional[float]:
    if not data:
        return None
    counts = Counter(data)
    total = float(len(data))
    entropy = -sum((count / total) * math.log2(count / total) for count in counts.values())
    return entropy


def _build_metrics(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(items)
    suspicious = sum(1 for it in items if it.get("obfuscation_score", 0) >= 6 or it.get("suspicious_tokens"))
    critical = sum(1 for it in items if it.get("high_risk"))
    errors = sum(1 for it in items if it.get("error"))
    by_host: Dict[str, int] = {}
    for it in items:
        host = it.get("host")
        if host:
            by_host[host] = by_host.get(host, 0) + 1
    return {
        "total_scripts": total,
        "suspicious_scripts": suspicious,
        "high_risk_scripts": critical,
        "error_count": errors,
        "by_host": by_host,
    }


def _print_record_summary(record: Dict[str, Any], *, verbose: bool) -> None:
    if record.get("error"):
        message = record.get("message")
        msg = "" if message is None else str(message).splitlines()[0]
        print(f"[analyze-js]    -> ERRO {record.get('error')}: {msg}")
        return
    status = record.get("status")
    size = record.get("size_bytes")
    size_part = f"{size}B" if isinstance(size, int) else "-"
    obf = record.get("obfuscation_score")
    tokens = list(record.get("suspicious_tokens") or [])
    token_categories = list(dict.fromkeys(record.get("token_categories") or []))
    potential_count = record.get("potential_ioc_count")
    if potential_count is None and "ioc_count" in record:
        potential_count = record.get("ioc_count")
    potential_display = potential_count if potential_count is not None else 0
    high_risk = record.get("high_risk")
    high_tag = " | HIGH" if high_risk else ""
    print(
        f"[analyze-js]    -> status={status} size={size_part} "
        f"obfuscation={obf} tokens={len(tokens)} categories={len(token_categories)} "
        f"potential_iocs={potential_display}{high_tag}"
    )
    if not verbose:
        return
    if tokens:
        print("[analyze-js]       tokens: " + ", ".join(tokens))
    if token_categories:
        print("[analyze-js]       categorias: " + ", ".join(token_categories))
    if verbose:
        owasp = record.get("owasp_refs")
        if owasp:
            print("[analyze-js]       OWASP: " + ", ".join(owasp))
        mitre = record.get("mitre_techniques")
        if mitre:
            print("[analyze-js]       MITRE: " + ", ".join(mitre))
    sample = record.get("potential_ioc_sample")
    if sample is None and "ioc_sample" in record:
        sample = record.get("ioc_sample")
    if sample:
        print("[analyze-js]       potential_ioc_sample:")
        for entry in sample:
            print(f"[analyze-js]         - {entry}")


def _persist(
    items: List[Dict[str, Any]],
    path: Path,
    *,
    source: Optional[str],
    meta_extra: Dict[str, Any],
    metrics: Dict[str, Any],
) -> None:
    payload = {
        "schema": SCHEMA,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "meta": {
            **({"source": source} if source else {}),
            **meta_extra,
        },
        "metrics": metrics,
        "items": items,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


__all__ = ["run"]
