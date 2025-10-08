"""Scanner de privacidade (modo Blacklight) usando navegador headless."""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

from .urls_utils import _same_site

try:  # pragma: no cover
    from playwright.sync_api import Playwright, TimeoutError as PlaywrightTimeout, sync_playwright
except Exception:  # pragma: no cover
    Playwright = None  # type: ignore
    sync_playwright = None  # type: ignore
    PlaywrightTimeout = Exception  # type: ignore


SCHEMA = "webcarto.privacy#2"


TRACKER_CATALOG: Dict[str, Dict[str, str]] = {
    "doubleclick.net": {"category": "ads", "label": "Google Marketing Platform"},
    "google-analytics.com": {"category": "analytics", "label": "Google Analytics"},
    "googletagmanager.com": {"category": "analytics", "label": "Google Tag Manager"},
    "g.doubleclick.net": {"category": "ads", "label": "Google Ads"},
    "facebook.com": {"category": "social", "label": "Facebook"},
    "facebook.net": {"category": "social", "label": "Facebook"},
    "connect.facebook.net": {"category": "social", "label": "Facebook"},
    "hotjar.com": {"category": "session_replay", "label": "Hotjar"},
    "fullstory.com": {"category": "session_replay", "label": "FullStory"},
    "mouseflow.com": {"category": "session_replay", "label": "Mouseflow"},
    "clarity.ms": {"category": "session_replay", "label": "Microsoft Clarity"},
    "mixpanel.com": {"category": "analytics", "label": "Mixpanel"},
    "segment.com": {"category": "analytics", "label": "Segment"},
    "criteo.com": {"category": "ads", "label": "Criteo"},
    "adservice.google": {"category": "ads", "label": "Google Ads"},
    "scorecardresearch.com": {"category": "analytics", "label": "Comscore"},
    "quantcast.com": {"category": "analytics", "label": "Quantcast"},
    "cookielaw.org": {"category": "consent", "label": "OneTrust"},
}


COOKIE_HINTS: Dict[str, Dict[str, str]] = {
    "_ga": {"category": "analytics", "label": "Google Analytics"},
    "_gid": {"category": "analytics", "label": "Google Analytics"},
    "_fbp": {"category": "ads", "label": "Facebook Pixel"},
    "_hj": {"category": "session_replay", "label": "Hotjar"},
    "ajs_anonymous_id": {"category": "analytics", "label": "Segment"},
    "ajs_user_id": {"category": "analytics", "label": "Segment"},
    "mp_": {"category": "analytics", "label": "Mixpanel"},
    "_gcl_": {"category": "ads", "label": "Google Ads"},
    "hubspotutk": {"category": "marketing", "label": "Hubspot"},
    "__hstc": {"category": "marketing", "label": "Hubspot"},
    "__hssc": {"category": "marketing", "label": "Hubspot"},
    "_clck": {"category": "session_replay", "label": "Microsoft Clarity"},
    "_clsk": {"category": "session_replay", "label": "Microsoft Clarity"},
}


TRACKER_CATEGORY_HINTS = {
    "ads",
    "advertising",
    "analytics",
    "marketing",
    "remarketing",
    "session_replay",
    "social",
    "tag_manager",
    "tracking",
}


SESSION_REPLAY_KEYWORDS = {
    "clarity",
    "fullstory",
    "hotjar",
    "mouseflow",
    "session replay",
    "session_replay",
}


TRACKER_KEYWORDS = {
    "analytics",
    "adservice",
    "doubleclick",
    "facebook",
    "fbp",
    "fbc",
    "gclid",
    "google",
    "hotjar",
    "mixpanel",
    "pixel",
    "segment",
    "tracker",
}


FACEBOOK_KEYWORDS = {
    "facebook",
    "fbp",
    "fbc",
    "fbclid",
}


GA_KEYWORDS = {
    "google analytics",
    "ga remarketing",
    "gac",
    "gclid",
    "_ga",
    "_gid",
    "_gcl_",
    "_dc_gtm",
}


INIT_INSTRUMENTATION = """
(() => {
  window.__privacyLogs = {
    keylogging: [],
    canvasFingerprint: false,
    audioFingerprint: false,
    storageWrites: [],
    facebookPixel: false,
    gaRemarketing: false,
  };

  const inputEvents = new Set(['input', 'keydown', 'keyup', 'keypress']);
  const originalAddEventListener = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function(type, listener, options) {
    try {
      if (inputEvents.has(type) && this instanceof Element && (this.matches('input') || this.matches('textarea'))) {
        const selector = this.id ? `#${this.id}` : this.getAttribute('name') ? `[name="${this.getAttribute('name')}"]` : this.tagName.toLowerCase();
        window.__privacyLogs.keylogging.push({ type, selector });
      }
    } catch (err) {
      // ignore
    }
    return originalAddEventListener.call(this, type, listener, options);
  };

  const markCanvas = () => { window.__privacyLogs.canvasFingerprint = true; };
  const canvasProto = HTMLCanvasElement.prototype;
  const ctxProto = CanvasRenderingContext2D && CanvasRenderingContext2D.prototype;
  if (canvasProto.toDataURL) {
    const original = canvasProto.toDataURL;
    canvasProto.toDataURL = function() { markCanvas(); return original.apply(this, arguments); };
  }
  if (ctxProto && ctxProto.getImageData) {
    const original = ctxProto.getImageData;
    ctxProto.getImageData = function() { markCanvas(); return original.apply(this, arguments); };
  }

  if (window.AudioContext) {
    const originalAudio = window.AudioContext;
    window.AudioContext = function() {
      window.__privacyLogs.audioFingerprint = true;
      return new originalAudio();
    };
  }

  const originalSetItem = Storage.prototype.setItem;
  Storage.prototype.setItem = function(key, value) {
    try {
      window.__privacyLogs.storageWrites.push({ storage: this === localStorage ? 'localStorage' : 'sessionStorage', key });
    } catch (err) {}
    return originalSetItem.apply(this, arguments);
  };

  const originalFetch = window.fetch;
  window.fetch = function(input, init) {
    try {
      const url = typeof input === 'string' ? input : input.url;
      if (url && url.includes('facebook.com/tr')) {
        window.__privacyLogs.facebookPixel = true;
      }
      if (url && url.includes('google-analytics.com/collect')) {
        const query = url.split('?')[1] || '';
        if (query.includes('t=dc')) { window.__privacyLogs.gaRemarketing = true; }
      }
    } catch (err) {}
    return originalFetch.apply(this, arguments);
  };
})();
"""


@dataclass
class NetworkLog:
    url: str
    method: str
    resource_type: str


@dataclass
class PageResult:
    page: str
    status: Optional[int]
    cookies: List[Dict[str, Any]] = field(default_factory=list)
    trackers: List[Dict[str, Any]] = field(default_factory=list)
    third_party_requests: List[str] = field(default_factory=list)
    keylogging: List[Dict[str, Any]] = field(default_factory=list)
    canvas_fingerprint: bool = False
    audio_fingerprint: bool = False
    facebook_pixel: bool = False
    ga_remarketing: bool = False
    storage_tracking: List[Dict[str, Any]] = field(default_factory=list)
    session_replay: bool = False
    consent_banner: bool = False
    issues: List[str] = field(default_factory=list)
    error: Optional[str] = None
    message: Optional[str] = None


def run(argv: Optional[Iterable[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if Playwright is None or sync_playwright is None:
        parser.error("Playwright não está instalado. Execute: pip install playwright && playwright install chromium")

    verbose = not args.quiet

    if args.url:
        targets = [args.url]
        source = args.url
    else:
        urls_payload = _load_json(args.urls, parser, label="URLs")
        if not urls_payload:
            parser.error("Nenhum URLs JSON encontrado e nenhuma --url fornecida")
        source = (urls_payload.get("meta") or {}).get("source")
        if source:
            targets = [source]
        else:
            pages = _extract_pages(urls_payload)
            if args.limit:
                pages = pages[: args.limit]
            targets = pages
            source = pages[0] if pages else None

    reputation_cache = _load_json(args.reputation)

    results: List[Dict[str, Any]] = []
    with sync_playwright() as p:
        for idx, target in enumerate(targets, start=1):
            page_url = target if isinstance(target, str) else target[0]
            if verbose:
                print(f"[privacy] [{idx}/{len(targets)}] navegando em {page_url}")
            try:
                result = _scan_with_browser(p, page_url, args=args, verbose=verbose)
            except Exception as exc:  # noqa: BLE001
                result = PageResult(page=page_url, status=None, error=type(exc).__name__, message=str(exc))
            result_dict = asdict(result)
            result_dict["index"] = idx
            result_dict["reputation"] = _lookup_reputation(page_url, reputation_cache)
            results.append(result_dict)

    payload = {
        "schema": SCHEMA,
        "generated_at": _now(),
        "meta": {
            "source": source,
            "targets": len(targets),
        },
        "metrics": _build_metrics(results),
        "items": results,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[privacy] Relatorio salvo em {args.output}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspeção de privacidade similar ao Blacklight")
    parser.add_argument("--urls", type=Path, default=Path("out/urls.json"), help="Envelope JSON do crawl")
    parser.add_argument("--url", help="Analisa apenas essa URL (ignora --urls)")
    parser.add_argument("--output", type=Path, default=Path("out/privacy.json"), help="Arquivo JSON de saída")
    parser.add_argument("--reputation", type=Path, default=Path("out/reputation.json"), help="Cache de reputação opcional")
    parser.add_argument("--limit", type=int, help="Limita a quantidade de páginas (modo --urls)")
    parser.add_argument("--timeout", type=int, default=20000, help="Timeout Playwright em milissegundos")
    parser.add_argument("--no-headless", action="store_true", help="Abre navegador visível (depuração)")
    parser.add_argument("--quiet", action="store_true", help="Reduz logs (padrão: exibe progresso)")
    return parser


def _scan_with_browser(playwright: Playwright, url: str, args: argparse.Namespace, *, verbose: bool) -> PageResult:
    browser = playwright.chromium.launch(headless=not args.no_headless)
    context = browser.new_context(ignore_https_errors=True)
    context.add_init_script(INIT_INSTRUMENTATION)
    requests_log: List[NetworkLog] = []

    def on_request(request):
        requests_log.append(NetworkLog(url=request.url, method=request.method, resource_type=request.resource_type))

    context.on("request", on_request)
    page = context.new_page()

    record = PageResult(page=url, status=None)
    try:
        try:
            response = page.goto(url, wait_until="networkidle", timeout=args.timeout)
        except PlaywrightTimeout:
            if verbose:
                print(f"[privacy]    -> aguardando apenas DOMContentLoaded em {url}")
            response = page.goto(url, wait_until="domcontentloaded", timeout=args.timeout)
        record.status = getattr(response, "status", None) if response else None
        _maybe_visit_secondary(page, url, args.timeout, verbose=verbose)
        record.cookies = _collect_cookies(context, url)
        record.trackers = _detect_trackers(requests_log, url)
        record.third_party_requests = _collect_third_party_requests(requests_log, url)
        privacy_logs = page.evaluate("window.__privacyLogs") or {}
        record.keylogging = privacy_logs.get("keylogging", [])
        record.canvas_fingerprint = bool(privacy_logs.get("canvasFingerprint"))
        record.audio_fingerprint = bool(privacy_logs.get("audioFingerprint"))
        record.facebook_pixel = bool(privacy_logs.get("facebookPixel"))
        record.ga_remarketing = bool(privacy_logs.get("gaRemarketing"))
        record.storage_tracking = privacy_logs.get("storageWrites", [])
        record.session_replay = any(t.get("category") == "session_replay" for t in record.trackers)
        record.consent_banner = _detect_consent_banner(page)
        _assign_cookie_issues(record)
        record.issues = _build_issues(record)
        if verbose:
            summary = (
                f"status={record.status} cookies={len(record.cookies)} "
                f"trackers={len(record.trackers)} issues={len(record.issues)}"
            )
            print(f"[privacy]    -> {summary}")
    except PlaywrightTimeout:
        record.error = "Timeout"
        record.message = f"Timeout ao carregar {url}"
        if verbose:
            print(f"[privacy]    -> timeout em {url}")
    finally:
        context.close()
        browser.close()
    return record


def _maybe_visit_secondary(page, base_url: str, timeout: int, *, verbose: bool) -> None:
    try:
        anchors: List[str] = page.evaluate(
            "Array.from(document.querySelectorAll('a[href]'))"
            ".map(a => a.getAttribute('href'))"
        )
    except Exception:
        anchors = []
    internal = []
    for href in anchors:
        if not href:
            continue
        if href.startswith("javascript:") or href.startswith("mailto:"):
            continue
        absolute = page.evaluate("(href) => new URL(href, location.href).href", href)
        try:
            if _same_site(absolute, base_url, include_subdomains=True):
                internal.append(absolute)
        except Exception:
            continue
    if not internal:
        return
    secondary = random.choice(internal)
    try:
        try:
            page.goto(secondary, wait_until="networkidle", timeout=timeout)
        except PlaywrightTimeout:
            if verbose:
                print(f"[privacy]    -> segunda página lenta, usando DOMContentLoaded: {secondary}")
            page.goto(secondary, wait_until="domcontentloaded", timeout=timeout)
    except PlaywrightTimeout:
        if verbose:
            print(f"[privacy]    -> timeout na segunda página {secondary}")


def _collect_cookies(context, page_url: str) -> List[Dict[str, Any]]:
    cookies_out: List[Dict[str, Any]] = []
    host = urlparse(page_url).hostname or ""
    try:
        cookies = context.cookies()
    except Exception:
        cookies = []
    for cookie in cookies:
        name = cookie.get("name")
        domain = cookie.get("domain")
        third_party = False
        try:
            third_party = domain and host and not _same_site(f"https://{domain.lstrip('.')}" , page_url, include_subdomains=True)
        except Exception:
            third_party = False
        hint = _match_cookie(name or "")
        cookies_out.append(
            {
                "name": name,
                "domain": domain,
                "expires": cookie.get("expires"),
                "secure": cookie.get("secure"),
                "httpOnly": cookie.get("httpOnly"),
                "sameSite": cookie.get("sameSite"),
                "third_party": bool(third_party),
                "category": hint.get("category") if hint else None,
                "label": hint.get("label") if hint else None,
                "issues": [],
            }
        )
    return cookies_out


def _detect_trackers(requests_log: List[NetworkLog], page_url: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen = set()
    for entry in requests_log:
        parsed = urlparse(entry.url)
        host = (parsed.hostname or "").lower()
        if not host or host in seen:
            continue
        seen.add(host)
        catalog_entry = _match_tracker(host)
        if catalog_entry:
            third_party = False
            try:
                third_party = not _same_site(entry.url, page_url, include_subdomains=True)
            except Exception:
                third_party = False
            out.append(
                {
                    "url": entry.url,
                    "host": host,
                    "category": catalog_entry.get("category"),
                    "label": catalog_entry.get("label"),
                    "third_party": bool(third_party),
                }
            )
    return out


def _collect_third_party_requests(requests_log: List[NetworkLog], page_url: str) -> List[str]:
    out: List[str] = []
    for entry in requests_log:
        try:
            if not _same_site(entry.url, page_url, include_subdomains=True):
                out.append(entry.url)
        except Exception:
            continue
    return sorted(set(out))


def _normalize_domain(value: Optional[str]) -> str:
    if not value:
        return ""
    lowered = value.strip().lower()
    return lowered[1:] if lowered.startswith(".") else lowered


def _hosts_match(cookie_domain: Optional[str], host: Optional[str]) -> bool:
    cd = _normalize_domain(cookie_domain)
    h = (host or "").strip().lower()
    if not cd or not h:
        return False
    return h == cd or h.endswith("." + cd) or cd.endswith("." + h)


def _detect_consent_banner(page) -> bool:
    try:
        lowered = page.content().lower()
    except Exception:
        return False
    keywords = ["cookie consent", "gdpr", "aceitar cookies", "lgpd", "we use cookies"]
    return any(keyword in lowered for keyword in keywords)


def _build_issues(record: PageResult) -> List[str]:
    issues: List[str] = []
    if record.error:
        issues.append("request_failed")
        return issues
    if any("third_party_cookies" in (c.get("issues") or []) or c.get("third_party") for c in record.cookies):
        issues.append("third_party_cookies")
    if record.trackers or any("trackers_detected" in (c.get("issues") or []) for c in record.cookies):
        issues.append("trackers_detected")
    if record.session_replay or any("session_replay" in (c.get("issues") or []) for c in record.cookies):
        issues.append("session_replay")
    if record.keylogging:
        issues.append("keylogging_listeners")
    if record.canvas_fingerprint or record.audio_fingerprint:
        issues.append("fingerprinting_signals")
    if record.facebook_pixel:
        issues.append("facebook_pixel")
    if record.ga_remarketing:
        issues.append("ga_remarketing")
    if record.storage_tracking:
        issues.append("storage_tracking")
    if not record.consent_banner and (record.cookies or record.trackers):
        issues.append("no_consent_banner")
    return issues


def _build_metrics(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(items)
    metrics: Dict[str, Any] = {
        "pages_analyzed": total,
        "pages_with_errors": sum(1 for it in items if it.get("error")),
        "pages_with_trackers": sum(1 for it in items if it.get("trackers")),
        "pages_with_third_party_cookies": sum(1 for it in items if any(c.get("third_party") for c in it.get("cookies", []))),
        "pages_with_keylogging": sum(1 for it in items if it.get("keylogging")),
        "pages_with_session_replay": sum(1 for it in items if it.get("session_replay")),
        "pages_with_fingerprinting": sum(1 for it in items if it.get("canvas_fingerprint") or it.get("audio_fingerprint")),
        "pages_with_facebook_pixel": sum(1 for it in items if it.get("facebook_pixel")),
        "pages_with_ga_remarketing": sum(1 for it in items if it.get("ga_remarketing")),
        "cookies_total": sum(len(it.get("cookies", [])) for it in items),
        "cookies_third_party_total": sum(1 for it in items for c in it.get("cookies", []) if c.get("third_party")),
    }
    return metrics


def _assign_cookie_issues(record: PageResult) -> None:
    tracker_hosts: List[Tuple[str, str]] = []
    for tracker in record.trackers:
        host = (tracker.get("host") or "").lower()
        category = (tracker.get("category") or "").lower()
        if host:
            tracker_hosts.append((host, category))

    facebook_flag = bool(record.facebook_pixel)
    ga_flag = bool(record.ga_remarketing)

    for cookie in record.cookies:
        issues = set(cookie.get("issues") or [])
        if cookie.get("third_party"):
            issues.add("third_party_cookies")

        category = (cookie.get("category") or "").strip().lower()
        label = (cookie.get("label") or "").strip().lower()
        name = (cookie.get("name") or "").strip().lower()
        domain = _normalize_domain(cookie.get("domain"))
        joined = " ".join(part for part in (category, label, name) if part)

        if category == "session_replay":
            issues.add("session_replay")
        if category in TRACKER_CATEGORY_HINTS:
            issues.add("trackers_detected")

        if any(keyword in joined for keyword in SESSION_REPLAY_KEYWORDS):
            issues.add("session_replay")
        if any(keyword in joined for keyword in TRACKER_KEYWORDS):
            issues.add("trackers_detected")

        for host, tracker_category in tracker_hosts:
            if _hosts_match(domain, host):
                issues.add("trackers_detected")
                if tracker_category == "session_replay":
                    issues.add("session_replay")

        if facebook_flag and (
            any(keyword in joined for keyword in FACEBOOK_KEYWORDS)
            or _hosts_match(domain, "facebook.com")
            or _hosts_match(domain, "facebook.net")
        ):
            issues.add("facebook_pixel")

        if ga_flag and any(keyword in joined for keyword in GA_KEYWORDS):
            issues.add("ga_remarketing")

        cookie["issues"] = sorted(issues)


def _extract_pages(urls_payload: Dict[str, Any]) -> List[str]:
    items = urls_payload.get("items", [])
    pages = sorted({it.get("page") for it in items if isinstance(it, dict) and it.get("page")})
    return [p for p in pages if isinstance(p, str)]


def _match_tracker(host: str) -> Optional[Dict[str, str]]:
    lowered = host.lower()
    for needle, entry in TRACKER_CATALOG.items():
        if needle in lowered:
            return entry
    return None


def _match_cookie(name: str) -> Optional[Dict[str, str]]:
    lowered = name.lower()
    for needle, entry in COOKIE_HINTS.items():
        if needle.lower() in lowered:
            return entry
    return None


def _lookup_reputation(page_url: str, reputation_payload: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not reputation_payload or not isinstance(reputation_payload, dict):
        return None
    items = reputation_payload.get("items")
    if not isinstance(items, dict):
        return None
    host = urlparse(page_url).hostname or ""
    return items.get(host)


def _load_json(path: Path, parser: Optional[argparse.ArgumentParser] = None, *, label: Optional[str] = None) -> Optional[Dict[str, Any]]:
    if not path.exists():
        if parser and label:
            parser.error(f"Arquivo de {label} não encontrado: {path}")
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        if parser and label:
            parser.error(f"Arquivo de {label} inválido: {path}")
        return None


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def asdict(result: PageResult) -> Dict[str, Any]:
    return {
        "page": result.page,
        "status": result.status,
        "cookies": result.cookies,
        "trackers": result.trackers,
        "third_party_requests": result.third_party_requests,
        "keylogging": result.keylogging,
        "canvas_fingerprint": result.canvas_fingerprint,
        "audio_fingerprint": result.audio_fingerprint,
        "facebook_pixel": result.facebook_pixel,
        "ga_remarketing": result.ga_remarketing,
        "storage_tracking": result.storage_tracking,
        "session_replay": result.session_replay,
        "consent_banner": result.consent_banner,
        "issues": result.issues,
        "error": result.error,
        "message": result.message,
    }


__all__ = ["run"]
