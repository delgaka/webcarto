import argparse
import datetime as _dt
import html
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


def load_json(path: Path) -> Optional[Dict[str, Any]]:
    """Load JSON data if the file exists, otherwise return None."""
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _escape(text: Any) -> str:
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    return html.escape(text, quote=True)


def _fmt_dt(ts: Optional[str]) -> str:
    if not ts:
        return ""
    try:
        dt = _dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S %Z").strip()
    except ValueError:
        return ts


def _build_metric_list(metrics: Dict[str, Any]) -> str:
    parts: List[str] = []
    for key, value in metrics.items():
        parts.append(_render_metric_card(key, value))
    return "".join(parts)


FRIENDLY_LABELS = {
    "pages_analyzed": "Páginas analisadas",
    "pages_with_errors": "Páginas com erro",
    "pages_with_trackers": "Páginas com trackers",
    "pages_with_third_party_cookies": "Páginas c/ cookies de terceiros",
    "pages_with_keylogging": "Keylogging detectado",
    "pages_with_session_replay": "Session replay",
    "pages_with_fingerprinting": "Fingerprinting",
    "pages_with_facebook_pixel": "Facebook Pixel",
    "pages_with_ga_remarketing": "GA remarketing",
    "cookies_total": "Total de cookies",
    "cookies_third_party": "Cookies de terceiros",
    "trackers_by_category": "Trackers por categoria",
    "top_flagged_hosts": "Principais hosts sinalizados",
    "reputation_summary": "Resumo de reputação",
    "by_provider_verdict": "Veredito por provedor",
    "reputation_by_provider_verdict": "Veredito por provedor",
    "privacy_pages_analyzed": "Páginas auditadas (privacidade)",
    "privacy_pages_with_errors": "Erros de privacidade",
    "privacy_pages_with_trackers": "Páginas com trackers",
    "privacy_pages_with_third_party_cookies": "Cookies de terceiros",
    "privacy_pages_with_keylogging": "Keylogging",
    "privacy_pages_with_session_replay": "Session replay",
    "privacy_pages_with_fingerprinting": "Fingerprinting",
    "privacy_pages_with_facebook_pixel": "Facebook Pixel",
    "privacy_pages_with_ga_remarketing": "GA remarketing",
    "privacy_cookies_total": "Cookies analisados",
    "privacy_cookies_third_party_total": "Cookies de terceiros (total)",
}


METRIC_ICONS = {
    "pages_analyzed": "🧭",
    "pages_with_errors": "⚠️",
    "pages_with_trackers": "📡",
    "pages_with_third_party_cookies": "🍪",
    "pages_with_keylogging": "⌨️",
    "pages_with_session_replay": "🎥",
    "pages_with_fingerprinting": "🆔",
    "pages_with_facebook_pixel": "📘",
    "pages_with_ga_remarketing": "📈",
    "cookies_total": "🍪",
    "cookies_third_party": "🍪",
    "trackers_by_category": "📊",
    "top_flagged_hosts": "📈",
    "reputation_summary": "🛡️",
    "by_provider_verdict": "🤝",
    "reputation_by_provider_verdict": "🤝",
    "privacy_pages_analyzed": "🧭",
    "privacy_pages_with_errors": "⚠️",
    "privacy_pages_with_trackers": "📡",
    "privacy_pages_with_third_party_cookies": "🍪",
    "privacy_pages_with_keylogging": "⌨️",
    "privacy_pages_with_session_replay": "🎥",
    "privacy_pages_with_fingerprinting": "🆔",
    "privacy_pages_with_facebook_pixel": "📘",
    "privacy_pages_with_ga_remarketing": "📈",
    "privacy_cookies_total": "🍪",
    "privacy_cookies_third_party_total": "🍪",
}


REPUTATION_VERDICT_LABELS = {
    "malicious": "Maliciosos",
    "suspicious": "Suspeitos",
    "clean": "Limpos",
    "unknown": "Desconhecidos",
}


JS_FLAG_LABELS = {
    "alto": "Alto risco",
    "suspeito": "Suspeitos",
    "ofuscado": "Ofuscação",
    "erro": "Com erro",
    "limpo": "Sem alerta",
}


def _friendly_name(key: str) -> str:
    key_lower = key.lower()
    if key_lower in FRIENDLY_LABELS:
        return FRIENDLY_LABELS[key_lower]
    return key.replace("_", " ").title()


def _metric_icon(key: str) -> str:
    return METRIC_ICONS.get(key.lower(), "📊")


def _format_metric_value(value: Any) -> str:
    if isinstance(value, dict):
        return ", ".join(f"{_friendly_name(str(k))}: {_format_metric_value(v)}" for k, v in value.items()) or "n/d"
    if isinstance(value, (list, tuple)):
        formatted = []
        for item in value:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                formatted.append(f"{item[0]} ({item[1]})")
            else:
                formatted.append(_format_metric_value(item))
        return ", ".join(formatted) or "n/d"
    if isinstance(value, bool):
        return "Sim" if value else "Não"
    return str(value)


def _merge_summary_metrics(risk_metrics: Dict[str, Any], reputation_metrics: Dict[str, Any], privacy_metrics: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(risk_metrics)
    if reputation_metrics:
        merged["reputation_summary"] = reputation_metrics
    if privacy_metrics:
        merged["privacy_summary"] = privacy_metrics
    return merged


def _normalize_verdict_value(value: Any) -> str:
    raw = str(value or "").strip().lower()
    if raw in REPUTATION_VERDICT_LABELS:
        return raw
    return "unknown"


def _consolidate_reputation_verdict(providers: Dict[str, Any]) -> str:
    order = {"malicious": 3, "suspicious": 2, "clean": 1, "unknown": 0}
    best = ("unknown", 0)
    for info in (providers or {}).values():
        payload = info
        if isinstance(info, dict) and isinstance(info.get("data"), dict):
            payload = info["data"]
        verdict = _normalize_verdict_value(payload.get("verdict") if isinstance(payload, dict) else payload)
        score = order.get(verdict, 0)
        if score > best[1]:
            best = (verdict, score)
    return best[0]


def _js_flags(entry: Dict[str, Any]) -> List[str]:
    flags: List[str] = []
    if entry.get("error"):
        flags.append("erro")
        return flags
    if entry.get("high_risk"):
        flags.append("alto")
    if entry.get("suspicious_tokens"):
        flags.append("suspeito")
    score = entry.get("obfuscation_score")
    if isinstance(score, (int, float)) and score >= 6:
        flags.append("ofuscado")
    if not flags:
        flags.append("limpo")
    return flags


def _slugify(text: str) -> str:
    cleaned = []
    for ch in text.lower():
        if ch.isalnum():
            cleaned.append(ch)
        elif ch in {" ", "-", "_"}:
            cleaned.append("-")
    slug = "".join(cleaned)
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip('-') or "other"


def _render_metric_card(key: str, value: Any) -> str:
    icon = _metric_icon(key)
    title = _friendly_name(key)
    if isinstance(value, dict):
        items = []
        for sub_key, sub_val in value.items():
            label = _friendly_name(str(sub_key))
            items.append(f"<span class=\"metric-chip\"><strong>{_escape(label)}</strong>: {_escape(_format_metric_value(sub_val))}</span>")
        content = "".join(items) or "<span class=\"metric-chip\">n/d</span>"
        return (
            "<div class=\"metric-block\">"
            f"<div class=\"metric-icon\">{icon}</div>"
            f"<div class=\"metric-title\">{_escape(title)}</div>"
            f"<div class=\"metric-list\">{content}</div>"
            "</div>"
        )
    if isinstance(value, (list, tuple)):
        list_html = "".join(
            f"<span class=\"metric-chip\">{_escape(_format_metric_value(item))}</span>" for item in value
        ) or "<span class=\"metric-chip\">n/d</span>"
        return (
            "<div class=\"metric-block\">"
            f"<div class=\"metric-icon\">{icon}</div>"
            f"<div class=\"metric-title\">{_escape(title)}</div>"
            f"<div class=\"metric-list\">{list_html}</div>"
            "</div>"
        )
    return (
        "<div class=\"metric-block\">"
        f"<div class=\"metric-icon\">{icon}</div>"
        f"<div class=\"metric-title\">{_escape(title)}</div>"
        f"<span class=\"metric-value\">{_escape(value)}</span>"
        "</div>"
    )


def _render_tags(tags: Iterable[str]) -> str:
    return "".join(f"<span class=\"tag\">{_escape(tag)}</span>" for tag in tags)


def _render_badges(items: Iterable[str], *, palette: str = "muted") -> str:
    palette_class = f"badge--{palette}" if palette else ""
    return "".join(f"<span class=\"badge {palette_class}\">{_escape(item)}</span>" for item in items)


def _render_cookie_badges(cookies: List[Dict[str, Any]]) -> str:
    if not cookies:
        return _render_badges(["Nenhum"], palette="muted")
    parts: List[str] = []
    for cookie in cookies:
        name = cookie.get("label") or cookie.get("name") or "cookie"
        category = cookie.get("category")
        third = cookie.get("third_party")
        text = f"{name}{' (' + category + ')' if category else ''}"
        palette = "warn" if third else "muted"
        parts.append(f"<span class=\"badge badge--{palette}\">{_escape(text)}</span>")
    return "".join(parts)


def _render_tracker_badges(trackers: List[Dict[str, Any]]) -> str:
    if not trackers:
        return _render_badges(["Nenhum"], palette="muted")
    parts: List[str] = []
    for tracker in trackers:
        label = tracker.get("label") or tracker.get("host") or "tracker"
        category = tracker.get("category")
        third = tracker.get("third_party")
        text = f"{label}{' (' + category + ')' if category else ''}"
        palette = "warn" if third else "muted"
        parts.append(f"<span class=\"badge badge--{palette}\">{_escape(text)}</span>")
    return "".join(parts)


ISSUE_LABELS = {
    "third_party_cookies": "Cookies de terceiros",
    "trackers_detected": "Trackers carregados",
    "session_replay": "Session replay",
    "keylogging_listeners": "Keylogging",
    "fingerprinting_signals": "Fingerprinting",
    "facebook_pixel": "Facebook Pixel",
    "ga_remarketing": "GA Remarketing",
    "storage_tracking": "Armazenamento local",
    "no_consent_banner": "Sem banner de consentimento",
    "request_failed": "Falha no carregamento",
}

def _render_issue_badges(issues: Iterable[str]) -> str:
    mapped = [ISSUE_LABELS.get(issue, issue.replace("_", " ")) for issue in issues]
    if not mapped:
        mapped = ["Nenhum"]
        palette = "muted"
        return _render_badges(mapped, palette=palette)
    parts: List[str] = []
    for issue in mapped:
        palette = "warn" if issue != "Nenhum" else "muted"
        parts.append(f"<span class=\"badge badge--{palette}\">{_escape(issue)}</span>")
    return "".join(parts)


def _resolve_url_type(url_value: Optional[str], risk_entry: Optional[Dict[str, Any]]) -> Tuple[str, str]:
    if not isinstance(url_value, str):
        return "unknown", "Desconhecido"
    if risk_entry:
        link_type = risk_entry.get("link_type")
        if isinstance(link_type, str) and link_type:
            return link_type, _friendly_link_type(link_type)
        ownership = risk_entry.get("ownership")
        if ownership == "external":
            return "external", "Externo"
    lower = url_value.lower()
    if lower.endswith(('.js', '.mjs')):
        return "asset:script", "Script"
    if lower.endswith('.css'):
        return "asset:style", "Estilo"
    if lower.endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico')):
        return "asset:image", "Imagem"
    if any(x in lower for x in ['form', 'submit']) and '?' in lower:
        return "form", "Formulário"
    return "page", "Página"


def _resolve_ownership(risk_entry: Optional[Dict[str, Any]]) -> str:
    if isinstance(risk_entry, dict):
        owner = risk_entry.get("ownership")
        if isinstance(owner, str):
            return owner
    return "unknown"


def _friendly_link_type(link_type: str) -> str:
    mapping = {
        "page": "Página",
        "asset:image": "Imagem",
        "asset:script": "Script",
        "asset:style": "Estilo",
        "form": "Formulário",
        "external": "Externo",
        "unknown": "Desconhecido",
    }
    return mapping.get(link_type, link_type.title())

def _render_provider_badges(providers: Dict[str, Any]) -> str:
    if not providers:
        return "<span class=\"empty\">Sem dados</span>"
    parts: List[str] = []
    for name, payload in sorted(providers.items()):
        data = payload
        if isinstance(payload, dict) and "data" in payload:
            maybe = payload.get("data")
            if isinstance(maybe, dict):
                data = maybe
        if not isinstance(data, dict):
            data = {}
        verdict = (data or {}).get("verdict") or "unknown"
        verdict_class = f"provider-verdict--{verdict.lower()}"
        score = data.get("score")
        categories = data.get("categories") or []
        categories_text = ", ".join(categories)
        parts.append(
            "<div class=\"provider-chip\">"
            f"<span class=\"provider-name\">{_escape(name.upper())}</span>"
            f"<span class=\"provider-verdict {verdict_class}\">{_escape(verdict.title())}</span>"
            f"<span class=\"provider-score\">{_escape(f'Score {score}' if score not in (None, '') else '')}</span>"
            f"<span class=\"provider-categories\">{_escape(categories_text)}</span>"
            "</div>"
        )
    return "".join(parts)


def render_report(
    title: str,
    urls: Optional[Dict[str, Any]],
    risk: Optional[Dict[str, Any]],
    reputation: Optional[Dict[str, Any]],
    js_analysis: Optional[Dict[str, Any]] = None,
    privacy: Optional[Dict[str, Any]] = None,
) -> str:
    generated_at = ""
    source = ""
    if risk:
        generated_at = risk.get("generated_at", "")
        source = (risk.get("meta") or {}).get("source", "")
    elif urls:
        source = (urls.get("meta") or {}).get("source", "")

    generated_display = _fmt_dt(generated_at)

    url_items = urls.get("items", []) if urls else []
    risk_items = risk.get("items", []) if risk else []
    risk_metrics = risk.get("metrics", {}) if risk else {}
    privacy_metrics = privacy.get("metrics", {}) if privacy else {}

    reputation_items: List[Dict[str, Any]] = []
    if reputation:
        for host, data in sorted((reputation.get("items") or {}).items()):
            providers = data.get("providers") or {}
            reputation_items.append({
                "host": host,
                "providers": providers,
                "last": data.get("last"),
            })

    risk_lookup = {
        entry.get("url"): entry for entry in risk_items if isinstance(entry, dict) and entry.get("url")
    }

    url_rows_parts: List[str] = []
    for item in url_items:
        url_value = item.get("url")
        page_value = item.get("page")
        url_type, type_label = _resolve_url_type(url_value, risk_lookup.get(url_value))
        ownership = _resolve_ownership(risk_lookup.get(url_value))
        css_class = f"url-type--{url_type.replace(':', '-')}"
        url_rows_parts.append(
            f"<tr data-type='{_escape(url_type)}' data-ownership='{_escape(ownership)}' class='{css_class}'>"
            f"<td>{_escape(page_value)}</td><td>{_escape(url_value)}</td><td>{_escape(type_label)}</td></tr>"
        )
    url_rows = "".join(url_rows_parts) or "<tr><td colspan=\"2\" class=\"empty\">Nenhuma URL encontrada.</td></tr>"

    reason_set: Dict[str, str] = {}
    risk_rows_parts: List[str] = []
    for entry in risk_items:
        url_val = entry.get("url")
        page_val = entry.get("page")
        tags_val = entry.get("tags") or []
        reasons_val = entry.get("reasons") or []
        score_val = entry.get("score")
        reason_slugs = []
        for reason in reasons_val:
            if isinstance(reason, str) and reason:
                slug = _slugify(reason)
                reason_slugs.append(slug)
                reason_set[slug] = reason
        data_reason_attr = " ".join(reason_slugs)
        risk_rows_parts.append(
            f"<tr data-reasons=\"{_escape(data_reason_attr)}\">"
            f"<td>{_escape(url_val)}</td>"
            f"<td>{_escape(page_val)}</td>"
            f"<td>{_render_tags(tags_val or [])}</td>"
            f"<td>{_escape(', '.join(reasons_val))}</td>"
            f"<td>{_escape(score_val)}</td>"
            "</tr>"
        )
    risk_rows = "".join(risk_rows_parts) or "<tr><td colspan=\"5\" class=\"empty\">Nenhum risco apontado.</td></tr>"
    if reason_set:
        reason_buttons = ["<button data-reason=\"all\" class=\"active\">Todos</button>"]
        for slug, label in sorted(reason_set.items(), key=lambda kv: kv[1].lower()):
            reason_buttons.append(f"<button data-reason=\"{slug}\">{_escape(label)}</button>")
        reason_filter_group = "<div class=\"reason-filter\" id=\"risk-reason-filter\">" + "".join(reason_buttons) + "</div>"
    else:
        reason_filter_group = ""

    reputation_rows = []
    verdict_counts: Dict[str, int] = {}
    for item in reputation_items:
        providers = item.get("providers") or {}
        combined = _consolidate_reputation_verdict(providers)
        verdict_counts[combined] = verdict_counts.get(combined, 0) + 1
        tokens = {combined}
        for prov_info in providers.values():
            payload = prov_info
            if isinstance(prov_info, dict) and isinstance(prov_info.get("data"), dict):
                payload = prov_info["data"]
            verdict = _normalize_verdict_value(payload.get("verdict") if isinstance(payload, dict) else payload)
            tokens.add(verdict)
        if not tokens:
            tokens.add("unknown")
        provider_html = _render_provider_badges(providers)
        reputation_rows.append(
            f"<tr data-verdict=\"{_escape(' '.join(sorted(tokens)))}\">"
            f"<td>{_escape(item['host'])}</td>"
            f"<td>{provider_html}</td>"
            "</tr>"
        )
    reputation_table_body = "".join(reputation_rows) or "<tr><td colspan=\"2\" class=\"empty\">Sem dados de reputação.</td></tr>"
    if verdict_counts:
        verdict_buttons = ["<button data-reason=\"all\" class=\"active\">Todos</button>"]
        for slug in ("malicious", "suspicious", "clean", "unknown"):
            if verdict_counts.get(slug):
                label = REPUTATION_VERDICT_LABELS.get(slug, slug.title())
                verdict_buttons.append(f"<button data-reason=\"{slug}\">{_escape(label)}</button>")
        reputation_filter_group = "<div class=\"reason-filter chip-row\" id=\"reputation-verdict-filter\">" + "".join(verdict_buttons) + "</div>"
    else:
        reputation_filter_group = ""

    js_items = js_analysis.get("items", []) if js_analysis else []
    js_metrics = js_analysis.get("metrics", {}) if js_analysis else {}
    js_rows_parts: List[str] = []
    js_flag_counts: Dict[str, int] = {}
    for entry in js_items:
        flags = _js_flags(entry)
        for flag in flags:
            js_flag_counts[flag] = js_flag_counts.get(flag, 0) + 1
        flag_tokens = " ".join(sorted(set(flags)))
        js_rows_parts.append(
            f"<tr data-flags=\"{_escape(flag_tokens)}\">"
            f"<td>{_escape(entry.get('url'))}</td>"
            f"<td>{_escape(entry.get('page'))}</td>"
            f"<td>{_escape(', '.join(entry.get('token_categories') or []))}</td>"
            f"<td>{_escape(', '.join(entry.get('owasp_refs') or []))}</td>"
            f"<td>{_escape(', '.join(entry.get('mitre_techniques') or []))}</td>"
            f"<td>{'HIGH' if entry.get('high_risk') else ''}</td>"
            "</tr>"
        )
    js_rows = "".join(js_rows_parts) or "<tr><td colspan=\"6\" class=\"empty\">Nenhum script analisado.</td></tr>"
    if js_flag_counts:
        js_buttons = ["<button data-reason=\"all\" class=\"active\">Todos</button>"]
        for slug in ("alto", "suspeito", "ofuscado", "erro", "limpo"):
            if js_flag_counts.get(slug):
                label = JS_FLAG_LABELS.get(slug, slug.title())
                js_buttons.append(f"<button data-reason=\"{slug}\">{_escape(label)}</button>")
        js_filter_group = "<div class=\"reason-filter chip-row\" id=\"js-flag-filter\">" + "".join(js_buttons) + "</div>"
    else:
        js_filter_group = ""

    combined_metrics = _merge_summary_metrics(risk_metrics, reputation.get("metrics", {}) if reputation else {}, privacy_metrics)
    metrics_html = _build_metric_list(combined_metrics)
    js_metrics_html = _build_metric_list(js_metrics)
    privacy_items = privacy.get("items", []) if privacy else []
    privacy_metrics = privacy.get("metrics", {}) if privacy else {}
    privacy_rows_parts: List[str] = []
    cookie_category_set: Dict[str, str] = {}
    for entry in privacy_items:
        cookies_html = _render_cookie_badges([c for c in entry.get("cookies", []) if c.get("third_party")])
        trackers_html = _render_tracker_badges(entry.get("trackers", []))
        issues_html = _render_issue_badges(entry.get("issues", []))
        issue_slugs = []
        for issue in entry.get("issues", []):
            if isinstance(issue, str) and issue:
                slug = _slugify(issue)
                issue_slugs.append(slug)
        issues_attr = " ".join(issue_slugs)
        privacy_rows_parts.append(
            f"<tr data-issues=\"{_escape(issues_attr)}\">"
            f"<td>{_escape(entry.get('page'))}</td>"
            f"<td>{_escape(entry.get('status'))}</td>"
            f"<td>{cookies_html}</td>"
            f"<td>{trackers_html}</td>"
            f"<td>{issues_html}</td>"
            "</tr>"
        )
    privacy_rows = "".join(privacy_rows_parts) or "<tr><td colspan=\"5\" class=\"empty\">Nenhuma analise de privacidade.</td></tr>"
    privacy_metrics_html = _build_metric_list(privacy_metrics)
    privacy_cookie_rows_parts: List[str] = []
    cookie_issue_set: Dict[str, str] = {}
    cookie_count = 0
    keylogging_rows_parts: List[str] = []
    storage_rows_parts: List[str] = []
    keylogging_count = 0
    storage_count = 0
    privacy_page_summaries: List[Dict[str, Any]] = []
    for entry in privacy_items:
        cookies = entry.get("cookies") or []
        page_label = entry.get("page")
        status_code = entry.get("status")
        trackers_entry = entry.get("trackers") or []
        third_party_cookie_count = sum(1 for c in cookies if c.get("third_party"))
        for cookie in cookies:
            cookie_count += 1
            name = cookie.get("name")
            domain = cookie.get("domain")
            category = cookie.get("category")
            category_slug = _slugify(category) if category else "sem-categoria"
            if category_slug not in cookie_category_set:
                cookie_category_set[category_slug] = category or "Sem categoria"
            is_third = bool(cookie.get("third_party"))
            origin = "Terceiro" if is_third else "Próprio"
            origin_slug = "third" if is_third else "first"
            origin_class = "cookie-origin-third" if origin_slug == "third" else "cookie-origin-first"
            cookie_issues = [
                issue
                for issue in (cookie.get("issues") or [])
                if isinstance(issue, str) and issue
            ]
            for slug in cookie_issues:
                label = ISSUE_LABELS.get(slug, slug.replace("_", " "))
                cookie_issue_set.setdefault(slug, label)
            issues_attr = " ".join(sorted(cookie_issues))
            issues_html = _render_issue_badges(cookie_issues)
            privacy_cookie_rows_parts.append(
                f"<tr data-origin=\"{origin_slug}\" data-category=\"{_escape(category_slug)}\" data-issues=\"{_escape(issues_attr)}\">"
                f"<td>{_escape(page_label)}</td>"
                f"<td>{_escape(name)}</td>"
                f"<td>{_escape(domain)}</td>"
                f"<td>{_escape(category or '')}</td>"
                f"<td>{issues_html}</td>"
                f"<td><span class=\"{origin_class}\">{_escape(origin)}</span></td>"
                "</tr>"
            )

        keylog_map: Dict[Tuple[str, str], int] = {}
        for ev in entry.get("keylogging", []) or []:
            ev_type = (ev.get("type") or "-").strip().lower()
            selector = (ev.get("selector") or "-").strip()
            key = (ev_type, selector)
            keylog_map[key] = keylog_map.get(key, 0) + 1
        for (ev_type, selector), count in sorted(keylog_map.items(), key=lambda kv: (kv[0][0], kv[0][1])):
            keylogging_count += count
            keylogging_rows_parts.append(
                "<tr>"
                f"<td>{_escape(page_label)}</td>"
                f"<td>{_escape(ev_type)}</td>"
                f"<td>{_escape(selector)}</td>"
                f"<td>{_escape(count)}x</td>"
                "</tr>"
            )

        storage_map: Dict[Tuple[str, str], int] = {}
        for log in entry.get("storage_tracking", []) or []:
            storage_type = (log.get("storage") or "-").strip().lower()
            key_name = (log.get("key") or "-").strip()
            skey = (storage_type, key_name)
            storage_map[skey] = storage_map.get(skey, 0) + 1
        for (stype, key_name), count in sorted(storage_map.items(), key=lambda kv: (kv[0][0], kv[0][1])):
            storage_count += count
            storage_rows_parts.append(
                "<tr>"
                f"<td>{_escape(page_label)}</td>"
                f"<td>{_escape(stype)}</td>"
                f"<td>{_escape(key_name)}</td>"
                f"<td>{_escape(count)}x</td>"
                "</tr>"
            )

        privacy_page_summaries.append(
            {
                "page": page_label,
                "status": status_code,
                "cookies_total": len(cookies),
                "cookies_third": third_party_cookie_count,
                "trackers_total": len(trackers_entry),
                "keylog_unique": len(keylog_map),
                "keylog_events": sum(keylog_map.values()),
                "storage_unique": len(storage_map),
                "storage_events": sum(storage_map.values()),
                "issues": entry.get("issues") or [],
                "session_replay": bool(entry.get("session_replay")),
                "facebook_pixel": bool(entry.get("facebook_pixel")),
                "ga_remarketing": bool(entry.get("ga_remarketing")),
                "keylogging": bool(keylog_map),
                "storage": bool(storage_map),
            }
        )

    privacy_cookie_count = cookie_count
    privacy_cookies_rows = "".join(privacy_cookie_rows_parts) or "<tr><td colspan=\"5\" class=\"empty\">Nenhum cookie capturado.</td></tr>"
    if cookie_issue_set:
        issue_buttons = ["<span class=\"filter-label\">Sinal detectado:</span>", "<button data-reason=\"all\" class=\"active\">Todos</button>"]
        for slug, label in sorted(cookie_issue_set.items(), key=lambda kv: kv[1].lower()):
            issue_buttons.append(f"<button data-reason=\"{slug}\">{_escape(label)}</button>")
        cookie_issue_filter = "<div class=\"reason-filter chip-row\" id=\"cookie-issue-filter\">" + "".join(issue_buttons) + "</div>"
    else:
        cookie_issue_filter = ""

    keylogging_table_rows = "".join(keylogging_rows_parts) or "<tr><td colspan=\"4\" class=\"empty\">Nenhum evento de teclado monitorado.</td></tr>"
    storage_table_rows = "".join(storage_rows_parts) or "<tr><td colspan=\"4\" class=\"empty\">Nenhum registro de armazenamento detectado.</td></tr>"

    privacy_page_cards_html = ""
    if privacy_page_summaries:
        profile_map: Dict[str, Dict[str, Any]] = {}
        for summary in privacy_page_summaries:
            issues_key = ",".join(sorted(summary.get("issues") or []))
            profile_key = "|".join(
                [
                    issues_key,
                    str(summary.get("keylogging")),
                    str(summary.get("session_replay")),
                    str(summary.get("storage")),
                    str(summary.get("facebook_pixel")),
                    str(summary.get("ga_remarketing")),
                ]
            )
            bucket = profile_map.setdefault(
                profile_key,
                {
                    "pages": [],
                    "issues": summary.get("issues") or [],
                    "keylogging": summary.get("keylogging"),
                    "session_replay": summary.get("session_replay"),
                    "storage": summary.get("storage"),
                    "facebook_pixel": summary.get("facebook_pixel"),
                    "ga_remarketing": summary.get("ga_remarketing"),
                    "cookies_third": 0,
                    "cookies_total": 0,
                    "trackers_total": 0,
                    "keylog_unique": 0,
                    "keylog_events": 0,
                    "storage_unique": 0,
                    "storage_events": 0,
                },
            )
            bucket["pages"].append(summary.get("page") or "-" )
            bucket["cookies_third"] += summary.get("cookies_third", 0)
            bucket["cookies_total"] += summary.get("cookies_total", 0)
            bucket["trackers_total"] += summary.get("trackers_total", 0)
            bucket["keylog_unique"] += summary.get("keylog_unique", 0)
            bucket["keylog_events"] += summary.get("keylog_events", 0)
            bucket["storage_unique"] += summary.get("storage_unique", 0)
            bucket["storage_events"] += summary.get("storage_events", 0)

        card_parts: List[str] = []
        for bucket in profile_map.values():
            pages = bucket["pages"]
            chips = [
                f"Páginas: {len(pages)}",
                f"Cookies de terceiros (total): {bucket['cookies_third']}",
                f"Cookies (total): {bucket['cookies_total']}",
                f"Trackers (total): {bucket['trackers_total']}",
                f"Keylogging: {'Sim' if bucket['keylogging'] else 'Não'} ({bucket['keylog_unique']} campos, {bucket['keylog_events']} eventos)",
                f"Session replay: {'Sim' if bucket['session_replay'] else 'Não'}",
                f"Armazenamento: {'Sim' if bucket['storage'] else 'Não'} ({bucket['storage_unique']} chaves, {bucket['storage_events']} gravações)",
                f"Facebook Pixel: {'Sim' if bucket['facebook_pixel'] else 'Não'}",
                f"GA remarketing: {'Sim' if bucket['ga_remarketing'] else 'Não'}",
            ]
            issues = [ISSUE_LABELS.get(issue, issue.replace("_", " ")) for issue in bucket.get("issues", [])]
            if issues:
                chips.append("Issues: " + ", ".join(issues))
            chips_html = "".join(f"<span class=\"metric-chip\">{_escape(text)}</span>" for text in chips)
            pages_html = "".join(f"<li>{_escape(page)}</li>" for page in pages)
            card_parts.append(
                "<div class=\"privacy-page-card\">"
                f"<div class=\"privacy-page-card__header\">{len(pages)} página(s) com este perfil</div>"
                f"<div class=\"metric-list\">{chips_html}</div>"
                f"<ul class=\"privacy-page-card__pages\">{pages_html}</ul>"
                "</div>"
            )
        privacy_page_cards_html = "<div class=\"privacy-page-cards\">" + "".join(card_parts) + "</div>"
    now_str = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

    html_doc = f"""<!DOCTYPE html>
<html lang=\"pt-BR\">
<head>
  <meta charset=\"utf-8\" />
  <title>{_escape(title)}</title>
  <style>
    :root {{
      color-scheme: light dark;
      --bg: #f8fafc;
      --fg: #0f172a;
      --accent: #2563eb;
      --card: #ffffffd9;
      --card-border: #e2e8f0;
      --muted: #475569;
      --tag-bg: #e0e7ff;
      --tag-fg: #1e3a8a;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: radial-gradient(circle at top, rgba(37,99,235,0.10), transparent 45%), var(--bg);
      color: var(--fg);
      min-height: 100vh;
    }}
    header {{
      padding: 32px 48px;
      background: linear-gradient(120deg, rgba(37,99,235,0.85), rgba(14,116,144,0.85));
      color: white;
      box-shadow: 0 4px 24px rgba(15,23,42,0.2);
    }}
    header h1 {{
      margin: 0 0 12px;
      font-size: 2.4rem;
      letter-spacing: 0.02em;
    }}
    header .meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 16px;
      font-size: 0.95rem;
      opacity: 0.92;
    }}
    main {{
      padding: 32px 48px 64px;
      display: flex;
      flex-direction: column;
      gap: 32px;
    }}
    section {{
      background: var(--card);
      border: 1px solid var(--card-border);
      border-radius: 16px;
      padding: 24px 28px;
      box-shadow: 0 8px 24px rgba(15,23,42,0.08);
      backdrop-filter: blur(6px);
    }}
    section h2 {{
      margin: 0 0 12px;
      font-size: 1.5rem;
    }}
    .metric-grid {{
      display: grid;
      gap: 16px;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    }}
    .metric-block {{
      background: rgba(148,163,184,0.12);
      padding: 16px;
      border-radius: 12px;
      display: flex;
      flex-direction: column;
      gap: 8px;
      position: relative;
    }}
    .metric-icon {{
      font-size: 1.6rem;
      color: rgba(37,99,235,0.8);
    }}
    .metric-title {{
      font-weight: 600;
      font-size: 0.95rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .metric-value {{
      font-size: 1.4rem;
      font-weight: 700;
      color: var(--fg);
    }}
    .metric-list {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }}
    .metric-chip {{
      background: rgba(37,99,235,0.12);
      color: var(--accent);
      padding: 4px 8px;
      border-radius: 999px;
      font-size: 0.85rem;
      margin-right: 6px;
      display: inline-block;
    }}
    .panel-nav {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin: 0 0 24px;
    }}
    .panel-nav button {{
      border: 1px solid rgba(37,99,235,0.4);
      background: rgba(37,99,235,0.08);
      color: var(--accent);
      padding: 10px 18px;
      border-radius: 999px;
      font-size: 0.95rem;
      cursor: pointer;
      transition: all 0.2s ease;
    }}
    .panel-nav button.active {{
      background: rgba(37,99,235,0.2);
      border-color: rgba(37,99,235,0.9);
      color: var(--fg);
      box-shadow: 0 4px 12px rgba(37,99,235,0.25);
    }}
    .privacy-subnav {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center;
      margin: 20px 0 12px;
    }}
    .privacy-subnav button {{
      border: 1px solid rgba(37,99,235,0.35);
      background: rgba(37,99,235,0.08);
      color: rgba(37,99,235,0.85);
      padding: 8px 14px;
      border-radius: 999px;
      font-size: 0.9rem;
      cursor: pointer;
      transition: all 0.2s ease;
    }}
    .privacy-subnav button.active {{
      background: rgba(37,99,235,0.2);
      border-color: rgba(37,99,235,0.9);
      color: rgba(15,23,42,0.95);
      box-shadow: 0 4px 12px rgba(37,99,235,0.25);
    }}
    .privacy-page-cards {{
      display: grid;
      gap: 16px;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      margin: 20px 0 8px;
    }}
    .privacy-page-card {{
      background: rgba(148,163,184,0.12);
      border: 1px solid rgba(148,163,184,0.2);
      border-radius: 14px;
      padding: 18px;
      display: flex;
      flex-direction: column;
      gap: 10px;
    }}
    .privacy-page-card__header {{
      font-weight: 600;
      font-size: 1rem;
      color: var(--fg);
      word-break: break-word;
    }}
    .privacy-page-card__status {{
      font-size: 0.85rem;
      color: rgba(71,85,105,0.95);
    }}
    .privacy-page-card__pages {{
      margin: 8px 0 0;
      padding-left: 18px;
      font-size: 0.85rem;
      color: rgba(71,85,105,0.95);
    }}
    .privacy-subviews {{
      display: flex;
      flex-direction: column;
      gap: 20px;
    }}
    .privacy-subview {{
      display: none;
    }}
    .privacy-subview.active {{
      display: block;
    }}
    section.panel {{
      display: none;
    }}
    section.panel.active {{
      display: block;
    }}
    .table-container {{
      width: 100%;
      overflow-x: auto;
      border-radius: 12px;
    }}
    .table-container table {{
      width: 100%;
      min-width: 640px;
      table-layout: fixed;
    }}
    table {{
      width: 100%;
      border-collapse: separate;
      border-spacing: 0;
      margin-top: 16px;
    }}
    th, td {{
      padding: 12px;
      border-bottom: 1px solid rgba(148,163,184,0.4);
      text-align: left;
      vertical-align: top;
      word-break: break-word;
      overflow-wrap: anywhere;
    }}
    th {{
      background: rgba(15,23,42,0.05);
      position: sticky;
      top: 0;
      backdrop-filter: blur(4px);
      z-index: 2;
    }}
    tbody tr:hover {{
      background: rgba(37,99,235,0.08);
    }}
    .tag {{
      display: inline-flex;
      align-items: center;
      margin: 0 6px 6px 0;
      padding: 4px 10px;
      border-radius: 999px;
      background: var(--tag-bg);
      color: var(--tag-fg);
      font-size: 0.78rem;
      font-weight: 600;
    }}
    .provider-chip {{
      display: inline-flex;
      flex-direction: column;
      gap: 4px;
      padding: 10px 12px;
      border-radius: 12px;
      background: rgba(37,99,235,0.10);
      margin: 6px 8px 6px 0;
      min-width: 160px;
    }}
    .provider-name {{
      font-weight: 700;
      font-size: 0.82rem;
      letter-spacing: 0.05em;
      color: rgba(15,23,42,0.85);
    }}
    .provider-verdict {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      width: fit-content;
    }}
    .provider-verdict--clean {{ background: rgba(34,197,94,0.18); color: #047857; }}
    .provider-verdict--suspicious {{ background: rgba(249,115,22,0.18); color: #c2410c; }}
    .provider-verdict--malicious {{ background: rgba(248,113,113,0.25); color: #b91c1c; }}
    .provider-verdict--unknown {{ background: rgba(148,163,184,0.2); color: rgba(30,41,59,0.8); }}
    .provider-score {{
      font-size: 0.72rem;
      color: rgba(37,99,235,0.9);
      font-weight: 600;
    }}
    .provider-categories {{
      font-size: 0.72rem;
      color: rgba(71,85,105,0.9);
    }}
    .empty {{ color: var(--muted); text-align: center; padding: 32px 0; }}
    .filters {{ display: flex; gap: 12px; flex-wrap: wrap; margin: 12px 0; align-items: center; }}
    .filter-label {{
      font-size: 0.85rem;
      font-weight: 600;
      color: rgba(71,85,105,0.95);
    }}
    .filters input {{
      padding: 10px 14px;
      border-radius: 12px;
      border: 1px solid rgba(148,163,184,0.7);
      min-width: 260px;
      font-size: 0.95rem;
      background: #ffffff;
      color: var(--fg);
      box-shadow: 0 2px 6px rgba(15,23,42,0.08);
      transition: box-shadow 0.2s ease, border-color 0.2s ease;
    }}
    .filters input::placeholder {{
      color: rgba(71,85,105,0.8);
    }}
    .filters input:focus {{
      outline: none;
      border-color: rgba(37,99,235,0.6);
      box-shadow: 0 0 0 3px rgba(37,99,235,0.25);
    }}
    .chip-groups {{ display: flex; flex-direction: column; gap: 8px; width: 100%; }}
    .chip-row {{ display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }}
    .type-filter, .reason-filter {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      align-items: center;
    }}
    .type-filter button, .reason-filter button {{
      border: 1px solid rgba(148,163,184,0.5);
      background: rgba(148,163,184,0.15);
      color: rgba(15,23,42,0.8);
      padding: 6px 12px;
      border-radius: 999px;
      font-size: 0.82rem;
      cursor: pointer;
      transition: all 0.2s ease;
    }}
    .type-filter button.active, .reason-filter button.active {{
      border-color: rgba(37,99,235,0.6);
      background: rgba(37,99,235,0.18);
      color: rgba(15,23,42,0.95);
      box-shadow: 0 4px 12px rgba(37,99,235,0.22);
    }}
    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      margin: 2px 6px 2px 0;
      border-radius: 999px;
      font-size: 0.78rem;
      font-weight: 600;
      letter-spacing: 0.01em;
    }}
    .badge--muted {{
      background: rgba(148,163,184,0.18);
      color: rgba(15,23,42,0.75);
    }}
    .badge--warn {{
      background: rgba(249,115,22,0.18);
      color: #ea580c;
      border: 1px solid rgba(234,88,12,0.3);
    }}
    .cookie-origin-first {{ color: rgba(34,197,94,0.8); font-weight: 600; }}
    .cookie-origin-third {{ color: rgba(234,88,12,0.85); font-weight: 600; }}
    footer {{
      text-align: center;
      padding: 24px 0 48px;
      font-size: 0.85rem;
      color: var(--muted);
    }}
    @media (max-width: 768px) {{
      header, main {{ padding: 24px; }}
      th, td {{ font-size: 0.85rem; }}
    }}
  </style>
  <script>
    function setupFilter(inputId, tableId) {{
      var input = document.getElementById(inputId);
      var table = document.getElementById(tableId);
      if (!input || !table) return;
      input.addEventListener('input', function() {{
        var filter = input.value.toLowerCase();
        Array.from(table.querySelectorAll('tbody tr')).forEach(function(row) {{
          var text = row.textContent.toLowerCase();
          row.style.display = text.indexOf(filter) > -1 ? '' : 'none';
        }});
      }});
    }}
    function setupTypeFilter(groupId, tableId) {{
      var group = document.getElementById(groupId);
      var table = document.getElementById(tableId);
      if (!group || !table) return;
      var buttons = Array.from(group.querySelectorAll('button'));
      buttons.forEach(function(btn) {{
        btn.addEventListener('click', function() {{
          buttons.forEach(function(b) {{ b.classList.toggle('active', b === btn); }});
          var target = btn.dataset.type;
          Array.from(table.querySelectorAll('tbody tr')).forEach(function(row) {{
            var match = true;
            if (target !== 'all') {{
              if (target === 'external') {{
                match = row.dataset.ownership === 'external';
              }} else {{
                match = row.dataset.type === target;
              }}
            }}
            row.style.display = match ? '' : 'none';
          }});
        }});
      }});
    }}
    function setupChipFilter(inputId, tableId, groupId, attrName) {{
      var input = document.getElementById(inputId);
      var table = document.getElementById(tableId);
      var group = document.getElementById(groupId);
      if (!table) return;
      var buttons = group ? Array.from(group.querySelectorAll('button')) : [];
      var activeValue = 'all';
      function applyFilters() {{
        var textFilter = input ? input.value.toLowerCase() : '';
        Array.from(table.querySelectorAll('tbody tr')).forEach(function(row) {{
          var text = row.textContent.toLowerCase();
          var tokens = (row.dataset[attrName] || '').split(' ').filter(Boolean);
          var matchChip = activeValue === 'all' || tokens.indexOf(activeValue) > -1;
          var matchText = !textFilter || text.indexOf(textFilter) > -1;
          row.style.display = matchChip && matchText ? '' : 'none';
        }});
      }}
      if (input) input.addEventListener('input', applyFilters);
      if (buttons.length) {{
        buttons.forEach(function(btn) {{
          btn.addEventListener('click', function() {{
            buttons.forEach(function(b) {{ b.classList.toggle('active', b === btn); }});
            activeValue = btn.dataset.reason || 'all';
            applyFilters();
          }});
        }});
      }}
      applyFilters();
    }}
    function setupCookieFilter(inputId, tableId, originGroupId, issueGroupId) {{
      var input = document.getElementById(inputId);
      var table = document.getElementById(tableId);
      var originGroup = document.getElementById(originGroupId);
      var issueGroup = document.getElementById(issueGroupId);
      if (!table) return;
      var originButtons = originGroup ? Array.from(originGroup.querySelectorAll('button')) : [];
      var issueButtons = issueGroup ? Array.from(issueGroup.querySelectorAll('button')) : [];
      var activeOrigin = 'all';
      var activeIssue = 'all';
      function applyFilters() {{
        var textFilter = input ? input.value.toLowerCase() : '';
        Array.from(table.querySelectorAll('tbody tr')).forEach(function(row) {{
          var text = row.textContent.toLowerCase();
          var origin = row.dataset.origin;
          var issues = (row.dataset.issues || '').split(' ').filter(Boolean);
          var matchOrigin = activeOrigin === 'all' || origin === activeOrigin;
          var matchIssue = activeIssue === 'all' || issues.indexOf(activeIssue) > -1;
          var matchText = !textFilter || text.indexOf(textFilter) > -1;
          row.style.display = matchOrigin && matchIssue && matchText ? '' : 'none';
        }});
      }}
      if (input) input.addEventListener('input', applyFilters);
      if (originButtons.length) {{
        originButtons.forEach(function(btn) {{
          btn.addEventListener('click', function() {{
            originButtons.forEach(function(b) {{ b.classList.toggle('active', b === btn); }});
            activeOrigin = btn.dataset.reason || 'all';
            applyFilters();
          }});
        }});
      }}
      if (issueButtons.length) {{
        issueButtons.forEach(function(btn) {{
          btn.addEventListener('click', function() {{
            issueButtons.forEach(function(b) {{ b.classList.toggle('active', b === btn); }});
            activeIssue = btn.dataset.reason || 'all';
            applyFilters();
          }});
        }});
      }}
      applyFilters();
    }}
    function setupPrivacySubnav() {{
      var nav = document.getElementById('privacy-subnav');
      if (!nav) return;
      var buttons = Array.from(nav.querySelectorAll('button[data-view]'));
      if (!buttons.length) return;
      var views = Array.from(document.querySelectorAll('.privacy-subview'));
      function activate(target) {{
        buttons.forEach(function(btn) {{
          btn.classList.toggle('active', btn.dataset.view === target);
        }});
        views.forEach(function(view) {{
          view.classList.toggle('active', view.dataset.view === target);
        }});
      }}
      buttons.forEach(function(btn) {{
        btn.addEventListener('click', function() {{
          activate(btn.dataset.view);
        }});
      }});
      activate(buttons[0].dataset.view);
    }}
    function setupPanels() {{
      var buttons = Array.from(document.querySelectorAll('.panel-nav button'));
      var panels = Array.from(document.querySelectorAll('section.panel'));
      if (!buttons.length || !panels.length) return;
      function activate(target) {{
        buttons.forEach(function(btn) {{
          btn.classList.toggle('active', btn.dataset.target === target);
        }});
        panels.forEach(function(panel) {{
          panel.classList.toggle('active', panel.dataset.panel === target);
        }});
      }}
      buttons.forEach(function(btn) {{
        btn.addEventListener('click', function() {{
          activate(btn.dataset.target);
        }});
      }});
      var initial = buttons.find(function(btn) {{ return btn.classList.contains('active'); }});
      activate(initial ? initial.dataset.target : buttons[0].dataset.target);
    }}
    document.addEventListener('DOMContentLoaded', function() {{
      setupFilter('urls-filter', 'urls-table');
      setupChipFilter('risk-filter', 'risk-table', 'risk-reason-filter', 'reasons');
      setupChipFilter('reputation-filter', 'reputation-table', 'reputation-verdict-filter', 'verdict');
      setupChipFilter('js-filter', 'js-table', 'js-flag-filter', 'flags');
      setupFilter('privacy-filter', 'privacy-table');
      setupCookieFilter('cookie-filter', 'cookie-table', 'cookie-type-filter', 'cookie-issue-filter');
      setupPrivacySubnav();
      setupTypeFilter('urls-type-filter', 'urls-table');
      setupPanels();
    }});
  </script>
</head>
<body>
  <header>
    <h1>{_escape(title.replace('Relatorio', 'Relatório'))}</h1>
    <div class=\"meta\">
      <div><strong>Fonte:</strong> {_escape(source) or 'n/d'}</div>
      <div><strong>Gerado em:</strong> {_escape(generated_display) or 'n/d'}</div>
      <div><strong>Compilado em:</strong> {_escape(now_str)}</div>
    </div>
  </header>
  <main>
    <div class=\"panel-nav\">
      <button data-target=\"summary\" class=\"active\">Resumo</button>
      <button data-target=\"urls\">URLs ({len(url_items)})</button>
      <button data-target=\"risk\">Riscos ({len(risk_items)})</button>
      <button data-target=\"reputation\">Reputação ({len(reputation_items)})</button>
      {'' if not js_analysis else f'<button data-target="js">Scripts ({len(js_items)})</button>'}
      {'' if not privacy else f'<button data-target="privacy">Privacidade ({len(privacy_items)})</button>'}
    </div>
    <section class=\"panel active\" data-panel=\"summary\">
      <h2>Resumo de metricas</h2>
      <p class=\"muted\">Valores agregados do relatorio de risco. Metricas adicionais aparecem como chips agrupados.</p>
      <div class=\"metric-grid\">{metrics_html or '<div class=\"empty\">Sem metricas carregadas.</div>'}</div>
    </section>

    <section class=\"panel\" data-panel=\"urls\">
      <h2>URLs coletadas ({len(url_items)})</h2>
      <div class=\"filters\">
        <input id=\"urls-filter\" type=\"search\" placeholder=\"Filtrar por URL ou página...\" aria-label=\"Filtro de URLs\" />
        <div class=\"type-filter\" id=\"urls-type-filter\">
          <button data-type="all" class="active">Tudo</button>
          <button data-type="page">Páginas</button>
          <button data-type="asset:script">Scripts</button>
          <button data-type="asset:style">Estilos</button>
          <button data-type="asset:image">Imagens</button>
          <button data-type="form">Formulários</button>
          <button data-type="external">Somente externos</button>
        </div>
      </div>
      <div class=\"table-container\">
        <table id=\"urls-table\">
          <thead>
            <tr><th>Página</th><th>URL</th><th>Tipo</th></tr>
          </thead>
          <tbody>
            {url_rows}
          </tbody>
        </table>
      </div>
    </section>

    <section class=\"panel\" data-panel=\"risk\">
      <h2>Itens de risco ({len(risk_items)})</h2>
      <div class=\"filters\">
        <input id=\"risk-filter\" type=\"search\" placeholder=\"Filtrar por risco...\" aria-label=\"Filtro de riscos\" />
        {reason_filter_group}
      </div>
      <div class=\"table-container\">
        <table id=\"risk-table\">
          <thead>
            <tr>
              <th>URL</th>
              <th>Pagina de origem</th>
              <th>Tags</th>
              <th>Motivos</th>
              <th>Score</th>
            </tr>
          </thead>
          <tbody>
            {risk_rows}
          </tbody>
        </table>
      </div>
    </section>

    <section class=\"panel\" data-panel=\"reputation\">
      <h2>Reputação por host ({len(reputation_items)})</h2>
      <div class=\"filters\">
        <input id=\"reputation-filter\" type=\"search\" placeholder=\"Filtrar por host ou provedor...\" aria-label=\"Filtro de reputação\" />
        {reputation_filter_group}
      </div>
      <div class=\"table-container\">
        <table id=\"reputation-table\">
          <thead>
            <tr>
              <th>Host</th>
              <th>Provedores</th>
            </tr>
          </thead>
          <tbody>
            {reputation_table_body}
          </tbody>
        </table>
      </div>
    </section>
    {'' if not js_analysis else f"""
    <section class=\"panel\" data-panel=\"js\">
      <h2>Analise de JavaScript ({len(js_items)})</h2>
      <p class=\"muted\">Scripts coletados no crawl e avaliados por heuristicas de seguranca.</p>
      <div class=\"metric-grid\">{js_metrics_html or '<div class=\"empty\">Sem metricas para scripts.</div>'}</div>
      <div class=\"filters\">
        <input id=\"js-filter\" type=\"search\" placeholder=\"Filtrar scripts por URL, pagina ou categoria...\" aria-label=\"Filtro de scripts\" />
        {js_filter_group}
      </div>
      <div class=\"table-container\">
        <table id=\"js-table\">
          <thead>
            <tr>
              <th>Script</th>
              <th>Página</th>
              <th>Categorias</th>
              <th>OWASP</th>
              <th>MITRE</th>
              <th>Flag</th>
            </tr>
          </thead>
          <tbody>
            {js_rows}
          </tbody>
        </table>
      </div>
    </section>
    """}
    {'' if not privacy else f"""
    <section class=\"panel\" data-panel=\"privacy\">
      <h2>Analise de Privacidade ({len(privacy_items)})</h2>
      <p class=\"muted\">Cookies, trackers e outros sinais coletados nas páginas visitadas.</p>
      <div class=\"metric-grid\">{privacy_metrics_html or '<div class=\"empty\">Sem metricas de privacidade.</div>'}</div>
      {privacy_page_cards_html}
      <div class=\"filters\">
        <input id=\"privacy-filter\" type=\"search\" placeholder=\"Filtrar por pagina, tracker ou cookie...\" aria-label=\"Filtro de privacidade\" />
      </div>
      <div class=\"table-container\">
        <table id=\"privacy-table\">
          <thead>
            <tr>
              <th>Pagina</th>
              <th>Status</th>
              <th>Cookies terceiros</th>
              <th>Trackers</th>
              <th>Issues</th>
            </tr>
          </thead>
          <tbody>
            {privacy_rows}
          </tbody>
        </table>
      </div>
      <div class=\"privacy-subnav\" id=\"privacy-subnav\">
        <span class=\"filter-label\">Ver detalhes:</span>
        <button data-view=\"cookies\" class=\"active\">Cookies analisados ({privacy_cookie_count})</button>
        {'' if not keylogging_count else f'<button data-view="keylogging">Teclas monitoradas ({keylogging_count})</button>'}
        {'' if not storage_count else f'<button data-view="storage">Armazenamento local ({storage_count})</button>'}
      </div>
      <div class=\"privacy-subviews\">
        <div class=\"privacy-subview active\" data-view=\"cookies\">
          <h3>Cookies analisados ({privacy_cookie_count})</h3>
          <div class=\"filters\">
            <input id=\"cookie-filter\" type=\"search\" placeholder=\"Filtrar por nome, dominio ou categoria...\" aria-label=\"Filtro de cookies\" />
          </div>
          <div class=\"chip-groups\">
            <div class=\"reason-filter chip-row\" id=\"cookie-type-filter\">
              <span class=\"filter-label\">Origem do cookie:</span>
              <button data-reason=\"all\" class=\"active\">Todos</button>
              <button data-reason=\"third\">Terceiros</button>
              <button data-reason=\"first\">Próprio</button>
            </div>
            {cookie_issue_filter}
          </div>
          <div class=\"table-container\">
            <table id=\"cookie-table\">
              <thead>
                <tr>
                  <th>Pagina</th>
                  <th>Nome</th>
                  <th>Domínio</th>
                  <th>Categoria</th>
                  <th>Issues</th>
                  <th>Origem</th>
                </tr>
              </thead>
              <tbody>
                {privacy_cookies_rows}
              </tbody>
            </table>
          </div>
        </div>
        {'' if not keylogging_count else f"""
        <div class=\"privacy-subview\" data-view=\"keylogging\">
          <h3>Teclas monitoradas ({keylogging_count})</h3>
          <div class=\"table-container\">
            <table id=\"keylogging-table\">
              <thead>
                <tr>
                  <th>Pagina</th>
                  <th>Evento</th>
                  <th>Elemento</th>
                  <th>Ocorrências</th>
                </tr>
              </thead>
              <tbody>
                {keylogging_table_rows}
              </tbody>
            </table>
          </div>
        </div>
        """}
        {'' if not storage_count else f"""
        <div class=\"privacy-subview\" data-view=\"storage\">
          <h3>Armazenamento detectado ({storage_count})</h3>
          <div class=\"table-container\">
            <table id=\"storage-table\">
              <thead>
                <tr>
                  <th>Pagina</th>
                  <th>Tipo</th>
                  <th>Chave</th>
                  <th>Ocorrências</th>
                </tr>
              </thead>
              <tbody>
                {storage_table_rows}
              </tbody>
            </table>
          </div>
        </div>
        """}
      </div>
    </section>
    """}
  </main>
  <footer>
    Gerado por WebCarto report_builder - {_escape(now_str)}
  </footer>
</body>
</html>
"""
    return html_doc


def run(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Gera um relatorio HTML unificado a partir dos arquivos JSON em um diretorio de saida do WebCarto.",
    )
    parser.add_argument(
        "--out-dir",
        default="out",
        help="Diretorio com urls.json, risk.json e reputation.json (padrao: out).",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Arquivo HTML de destino (padrao: <out-dir>/report.html).",
    )
    parser.add_argument(
        "--title",
        default="Relatorio WebCarto",
        help="Titulo mostrado no topo do relatorio.",
    )

    args = parser.parse_args(argv)
    out_dir = Path(args.out_dir)
    if not out_dir.exists():
        raise SystemExit(f"Diretorio nao encontrado: {out_dir}")

    urls = load_json(out_dir / "urls.json")
    risk = load_json(out_dir / "risk.json")
    reputation = load_json(out_dir / "reputation.json")
    js_analysis = load_json(out_dir / "js-analysis.json")
    privacy = load_json(out_dir / "privacy.json")

    if not any([urls, risk, reputation, js_analysis, privacy]):
        raise SystemExit("Nenhum arquivo de saida encontrado para compor o relatorio.")

    html_doc = render_report(args.title, urls, risk, reputation, js_analysis, privacy)

    output_path = Path(args.output) if args.output else out_dir / "report.html"
    output_path.write_text(html_doc, encoding="utf-8")
    print(f"Relatorio salvo em {output_path}")
    return 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
