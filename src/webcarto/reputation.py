from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Any, Iterable, Optional, Tuple, List
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl
import json
import time
import os
import requests


DEFAULT_CACHE_PATH = "out/reputation-cache.json"
LEGACY_CACHE_PATH = "out/reputation.json"


def _now_ts() -> float:
    return time.time()


def parse_ttl(ttl: str) -> int:
    """Converte TTL em segundos. Aceita '7d', '24h', '3600s' ou inteiros.
    Retorna 0 em entradas inválidas.
    """
    if ttl is None:
        return 0
    s = str(ttl).strip().lower()
    try:
        if s.endswith("d"):
            return int(float(s[:-1]) * 86400)
        if s.endswith("h"):
            return int(float(s[:-1]) * 3600)
        if s.endswith("m"):
            return int(float(s[:-1]) * 60)
        if s.endswith("s"):
            return int(float(s[:-1]))
        return int(float(s))
    except Exception:
        return 0


def scrub_url(url: str, *, include_query: bool, scrub_params: Iterable[str]) -> Tuple[str, str]:
    """Normaliza URL para consulta de reputação.

    - include_query=False: remove querystring completamente.
    - include_query=True: mantém, mas remove chaves listadas em scrub_params (case-insensitive).
    - Retorna (url_scrubbed, source) onde source é 'url' ou 'host'.
    """
    p = urlparse(url)
    if not include_query:
        # Consultas por host são suficientes para muitos provedores
        host = (p.hostname or "").lower()
        return host, "host"
    # incluir query, mas limpando chaves sensíveis/de tracking
    keys = {k.lower() for k in scrub_params}
    params: List[Tuple[str, str]] = []
    for k, v in parse_qsl(p.query, keep_blank_values=True):
        if k.lower() in keys or k.lower().startswith("utm_"):
            continue
        params.append((k, v))
    new_qs = urlencode(params, doseq=True)
    cleaned = urlunparse((p.scheme, p.netloc, p.path, p.params, new_qs, p.fragment))
    return cleaned, "url"


@dataclass
class ProviderInfo:
    name: str
    requires_key: bool = False


DEFAULT_PROVIDERS: Dict[str, ProviderInfo] = {
    "vt": ProviderInfo("vt", requires_key=True),
    "gsb": ProviderInfo("gsb", requires_key=True),
    # URLhaus lookup via API requer Auth-Key (bulk API)
    "urlhaus": ProviderInfo("urlhaus", requires_key=True),
    "otx": ProviderInfo("otx", requires_key=True),
}


class ReputationClient:
    def __init__(
        self,
        *,
        providers: Optional[List[str]] = None,
        keys: Optional[Dict[str, str]] = None,
        cache_path: Optional[str] = None,
        ttl_seconds: int = 0,
        include_query: bool = False,
        scrub_params: Optional[List[str]] = None,
        concurrency: int = 2,
        timeout: int = 10,
        strict: bool = False,
        dry_run: bool = False,
        verbose: bool = False,
    ) -> None:
        self.verbose = verbose
        default_cache = cache_path or DEFAULT_CACHE_PATH
        legacy_fallback = None
        if cache_path is None and not os.path.exists(default_cache) and os.path.exists(LEGACY_CACHE_PATH):
            legacy_fallback = LEGACY_CACHE_PATH
        self.cache_path = default_cache
        self.ttl = int(max(0, ttl_seconds))
        self.include_query = bool(include_query)
        self.scrub_params = list(scrub_params or ["gclid", "fbclid", "trk", "ref", "src"])  # utm_* é tratado no scrub
        self.concurrency = int(max(1, int(concurrency)))
        self.timeout = int(max(1, int(timeout)))
        self.strict = bool(strict)
        self.dry_run = bool(dry_run)
        self.env_keys = {
            "vt": os.environ.get("VT_API_KEY"),
            "gsb": os.environ.get("GSB_API_KEY"),
            "otx": os.environ.get("OTX_API_KEY"),
            "urlhaus": os.environ.get("URLHAUS_AUTH_KEY"),
        }
        if keys:
            self.env_keys.update({k.lower(): v for k, v in keys.items()})
        self.providers = self._resolve_providers(providers)
        cache_source = legacy_fallback or self.cache_path
        self.cache = self._load_cache(cache_source)
        if legacy_fallback and legacy_fallback != self.cache_path:
            # migrate silently to the new cache path
            try:
                os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
                with open(self.cache_path, "w", encoding="utf-8") as f:
                    json.dump(self.cache, f, ensure_ascii=False, indent=2)
            except Exception:
                pass

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(f"[reputation] {msg}")

    def _resolve_providers(self, providers_arg: Optional[List[str]]) -> List[str]:
        # Se o usuário explicitou, filtra pelos existentes e requisitos de chave
        if providers_arg:
            out: List[str] = []
            missing: List[str] = []
            for p in [x.strip().lower() for x in providers_arg if x.strip()]:
                info = DEFAULT_PROVIDERS.get(p)
                if not info:
                    self._log(f"ignorado provider desconhecido: {p}")
                    continue
                if info.requires_key and not self.env_keys.get(p):
                    missing.append(p)
                    continue
                out.append(p)
            if missing and self.strict:
                raise RuntimeError(f"Providers exigem chave ausente: {','.join(missing)}")
            if missing:
                self._log(f"sem chave para: {','.join(missing)} (ignorados)")
            self._log(f"providers selecionados: {','.join(out) if out else '-'}")
            return out
        # Auto: inclui sem chave + com chave presente
        auto: List[str] = []
        for p, info in DEFAULT_PROVIDERS.items():
            if info.requires_key:
                if self.env_keys.get(p):
                    auto.append(p)
            else:
                auto.append(p)
        self._log(f"providers (auto): {','.join(auto) if auto else '-'}")
        return auto

    def _load_cache(self, path: str) -> Dict[str, Any]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"items": {}, "meta": {"version": 1}}

    def _save_cache(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
            with open(self.cache_path, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def _cache_get(self, key: str, provider: str) -> Optional[Dict[str, Any]]:
        it = self.cache.get("items", {}).get(key)
        if not it:
            return None
        pr = it.get("providers", {}).get(provider)
        if not pr:
            return None
        ts = pr.get("ts")
        if not ts:
            return None
        if self.ttl > 0 and (_now_ts() - float(ts)) > self.ttl:
            return None
        return pr.get("data")

    def _cache_set(self, key: str, provider: str, data: Dict[str, Any]) -> None:
        items = self.cache.setdefault("items", {})
        it = items.setdefault(key, {"providers": {}, "last": _now_ts()})
        it["providers"][provider] = {"ts": _now_ts(), "data": data}
        it["last"] = _now_ts()

    def _query_provider(self, provider: str, key: str, source: str) -> Dict[str, Any]:
        """Consulta um provider específico e retorna um veredicto padronizado.

        - provider: vt|gsb|urlhaus|otx
        - key: pode ser host (quando source='host') ou URL (quando source='url') conforme scrub_url.
        - source: 'host' ou 'url' (informativo).
        """
        if self.dry_run:
            return {"verdict": "unknown", "score": 0, "categories": [], "source": source}
        try:
            if provider == "urlhaus":
                api = self.env_keys.get("urlhaus")
                if not api:
                    return {"verdict": "unknown", "score": 0, "categories": [], "source": source}
                # A API de lookup usa o endpoint /v1/url/ com Auth-Key
                # Usar URL completa quando possível; se vier apenas host, criar uma URL sintética
                target_url = key if source == "url" else f"http://{key}/"
                resp = requests.post(
                    "https://urlhaus-api.abuse.ch/v1/url/",
                    data={"url": target_url},
                    headers={"User-Agent": "webcarto/0.1", "Accept": "application/json", "Auth-Key": api},
                    timeout=self.timeout,
                )
                data = resp.json() if resp.ok else {}
                qs = str(data.get("query_status", "")).lower()
                if qs == "ok":
                    # Quando há match, considerar malicioso
                    return {"verdict": "malicious", "score": 7, "categories": ["urlhaus"], "source": source}
                if qs in {"no_results", "no_results_found"}:
                    return {"verdict": "clean", "score": 0, "categories": [], "source": source}
                return {"verdict": "unknown", "score": 0, "categories": [], "source": source}

            if provider == "vt":
                api = self.env_keys.get("vt")
                if not api:
                    return {"verdict": "unknown", "score": 0, "categories": [], "source": source}
                headers = {"x-apikey": api}
                # Preferir domínio para reduzir cardinalidade
                host = key if source == "host" else requests.utils.urlparse(key).hostname or key
                url = f"https://www.virustotal.com/api/v3/domains/{host}"
                resp = requests.get(url, headers=headers, timeout=self.timeout)
                data = resp.json() if resp.ok else {}
                stats = (((data.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {})
                mal = int(stats.get("malicious", 0))
                susp = int(stats.get("suspicious", 0))
                if mal > 0:
                    return {"verdict": "malicious", "score": 7, "categories": [], "source": "host"}
                if susp > 0:
                    return {"verdict": "suspicious", "score": 3, "categories": [], "source": "host"}
                return {"verdict": "clean", "score": 0, "categories": [], "source": "host"}

            if provider == "gsb":
                api = self.env_keys.get("gsb")
                if not api:
                    return {"verdict": "unknown", "score": 0, "categories": [], "source": source}
                target = key if source == "url" else f"http://{key}/"
                body = {
                    "client": {"clientId": "webcarto", "clientVersion": "0.1"},
                    "threatInfo": {
                        "threatTypes": [
                            "MALWARE",
                            "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION",
                        ],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": target}],
                    },
                }
                resp = requests.post(
                    f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api}",
                    json=body,
                    timeout=self.timeout,
                )
                data = resp.json() if resp.ok else {}
                matches = data.get("matches") or []
                if matches:
                    return {"verdict": "malicious", "score": 7, "categories": [], "source": source}
                return {"verdict": "clean", "score": 0, "categories": [], "source": source}

            if provider == "otx":
                api = self.env_keys.get("otx")
                if not api:
                    return {"verdict": "unknown", "score": 0, "categories": [], "source": source}
                host = key if source == "host" else requests.utils.urlparse(key).hostname or key
                headers = {"X-OTX-API-KEY": api}
                resp = requests.get(
                    f"https://otx.alienvault.com/api/v1/indicators/domain/{host}/general",
                    headers=headers,
                    timeout=self.timeout,
                )
                data = resp.json() if resp.ok else {}
                pulses = (((data.get("pulse_info") or {}).get("count")) or 0)
                if pulses and int(pulses) > 0:
                    return {"verdict": "suspicious", "score": 3, "categories": ["otx:pulse"], "source": "host"}
                return {"verdict": "clean", "score": 0, "categories": [], "source": "host"}

            # Fallback desconhecido
            return {"verdict": "unknown", "score": 0, "categories": [], "source": source}
        except Exception:
            return {"verdict": "unknown", "score": 0, "categories": [], "source": source}

    def check_urls(self, urls: Iterable[str]) -> Dict[str, Dict[str, Any]]:
        """Consulta reputação para um conjunto de URLs (deduplicadas por chave).
        Retorna: map[url_original -> { provider -> data }].
        """
        results: Dict[str, Dict[str, Any]] = {}
        # Dedup por chave de consulta (host/url pós-scrub)
        key_map: Dict[str, Tuple[str, str]] = {}
        urls = list(urls)
        self._log(f"preparando {len(urls)} URL(s) para reputação")
        for u in urls:
            key, source = scrub_url(u, include_query=self.include_query, scrub_params=self.scrub_params)
            key_map[u] = (key, source)
            self._log(f"key='{key}' source={source} <- {u}")

        for i, (url, (key, source)) in enumerate(key_map.items(), start=1):
            self._log(f"[{i}/{len(key_map)}] consultando providers para key='{key}'")
            pr_map: Dict[str, Any] = {}
            for prov in self.providers:
                cached = self._cache_get(key, prov)
                if cached is not None:
                    self._log(f"cache HIT {prov} key='{key}' -> {cached.get('verdict')}")
                    pr_map[prov] = cached
                    continue
                # Consulta (stub) e salva
                self._log(f"cache MISS {prov} key='{key}' (consultando)")
                data = self._query_provider(prov, key, source)
                self._log(f"{prov} key='{key}' -> {data.get('verdict')}")
                pr_map[prov] = data
                self._cache_set(key, prov, data)
            results[url] = pr_map

        self._save_cache()
        return results

    def self_test(self) -> Dict[str, Any]:
        """Valida rapidamente providers configurados/chaves e conectividade.

        Retorno por provider: {status: ok|no_key|skipped|fail, http_status, note, error}
        - Respeita timeout configurado; ignora cache; não altera itens do cache.
        - Em dry_run, marca todos como skipped (dry-run).
        """
        out: Dict[str, Any] = {}
        if self.dry_run:
            for p in self.providers:
                out[p] = {"status": "skipped", "http_status": None, "note": "dry-run", "error": None}
            return out
        sess = requests.Session()
        for p in self.providers:
            self._log(f"self-test provider={p}")
            try:
                if p == "urlhaus":
                    api = self.env_keys.get("urlhaus")
                    if not api:
                        out[p] = {"status": "no_key", "http_status": None, "note": None, "error": None}
                        continue
                    r = sess.post(
                        "https://urlhaus-api.abuse.ch/v1/url/",
                        data={"url": "http://example.com/"},
                        headers={"User-Agent": "webcarto/0.1", "Accept": "application/json", "Auth-Key": api},
                        timeout=self.timeout,
                    )
                    js = r.json() if r.ok else {}
                    ok = (r.status_code == 200) and (js.get("query_status") in {"ok", "no_results", "no_results_found"})
                    out[p] = {"status": "ok" if ok else "fail", "http_status": r.status_code, "note": js.get("query_status"), "error": None if ok else "unexpected response"}
                    self._log(f"self-test urlhaus status={out[p]['status']} http={out[p]['http_status']} note={out[p]['note']}")
                    continue
                if p == "vt":
                    api = self.env_keys.get("vt")
                    if not api:
                        out[p] = {"status": "no_key", "http_status": None, "note": None, "error": None}
                        continue
                    h = {"x-apikey": api}
                    r = sess.get("https://www.virustotal.com/api/v3/domains/example.com", headers=h, timeout=self.timeout)
                    out[p] = {"status": "ok" if r.status_code == 200 else "fail", "http_status": r.status_code, "note": None, "error": None if r.status_code == 200 else "http"}
                    self._log(f"self-test vt status={out[p]['status']} http={out[p]['http_status']}")
                    continue
                if p == "gsb":
                    api = self.env_keys.get("gsb")
                    if not api:
                        out[p] = {"status": "no_key", "http_status": None, "note": None, "error": None}
                        continue
                    body = {
                        "client": {"clientId": "webcarto", "clientVersion": "0.1"},
                        "threatInfo": {
                            "threatTypes": ["MALWARE"],
                            "platformTypes": ["ANY_PLATFORM"],
                            "threatEntryTypes": ["URL"],
                            "threatEntries": [{"url": "http://example.com/"}],
                        },
                    }
                    r = sess.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api}", json=body, timeout=self.timeout)
                    # 200 com corpo (possivelmente vazio) já significa chamada válida
                    out[p] = {"status": "ok" if r.status_code == 200 else "fail", "http_status": r.status_code, "note": None, "error": None if r.status_code == 200 else "http"}
                    self._log(f"self-test gsb status={out[p]['status']} http={out[p]['http_status']}")
                    continue
                if p == "otx":
                    api = self.env_keys.get("otx")
                    if not api:
                        out[p] = {"status": "no_key", "http_status": None, "note": None, "error": None}
                        continue
                    h = {"X-OTX-API-KEY": api}
                    r = sess.get("https://otx.alienvault.com/api/v1/pulses/subscribed", headers=h, timeout=self.timeout)
                    ok = r.status_code in (200, 204)
                    out[p] = {"status": "ok" if ok else "fail", "http_status": r.status_code, "note": None, "error": None if ok else "http"}
                    self._log(f"self-test otx status={out[p]['status']} http={out[p]['http_status']}")
                    continue
                out[p] = {"status": "skipped", "http_status": None, "note": "unknown provider", "error": None}
            except Exception as e:
                out[p] = {"status": "fail", "http_status": None, "note": None, "error": type(e).__name__}
                self._log(f"self-test {p} error={type(e).__name__}")
        return out


def consolidate_verdict(provider_data: Dict[str, Any]) -> str:
    """Pega um map de provider->data e retorna o pior veredicto consolidado.
    Ordem: malicious > suspicious > clean > unknown.
    """
    order = {"malicious": 3, "suspicious": 2, "clean": 1, "unknown": 0}
    best = ("unknown", 0)
    for v in provider_data.values():
        ver = str(v.get("verdict", "unknown")).lower()
        sc = order.get(ver, 0)
        if sc > best[1]:
            best = (ver, sc)
    return best[0]


def build_reputation_metrics(results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Gera métricas agregadas de reputação para o relatório (ID 17)."""
    summary = {"malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0}
    by_provider_verdict: Dict[str, Dict[str, int]] = {}
    from urllib.parse import urlparse
    flagged_hosts: Dict[str, int] = {}
    for url, pdata in results.items():
        v = consolidate_verdict(pdata)
        summary[v] = summary.get(v, 0) + 1
        for p, info in pdata.items():
            pv = str(info.get("verdict", "unknown")).lower()
            by_provider_verdict.setdefault(p, {})[pv] = by_provider_verdict.setdefault(p, {}).get(pv, 0) + 1
        if v in ("malicious", "suspicious"):
            host = (urlparse(url).hostname or "").lower()
            if host:
                flagged_hosts[host] = flagged_hosts.get(host, 0) + 1
    top_external_hosts = sorted(flagged_hosts.items(), key=lambda x: (-x[1], x[0]))[:10]
    return {
        "reputation_summary": summary,
        "by_provider_verdict": by_provider_verdict,
        "top_flagged_hosts": top_external_hosts,
    }
