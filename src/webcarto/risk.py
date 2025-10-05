from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, unquote_plus, urlencode, urlunparse, urljoin
import base64
import ipaddress
from .urls_utils import _domain_of_url, _same_site


SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd", "buff.ly", "ow.ly",
    "rebrand.ly", "lnkd.in", "t.ly", "bit.do", "cutt.ly", "rb.gy",
}

PASTE_SITES = {
    "pastebin.com", "hastebin.com", "gist.github.com", "paste.ee", "ghostbin.com",
}

WEBHOOK_PATTERNS = (
    "hooks.slack.com/",
    "discord.com/api/webhooks/",
    "discordapp.com/api/webhooks/",
)

RISKY_TLDS = {
    "ru", "tk", "gq", "cf", "ga", "ml", "xyz", "top", "zip", "click",
    "country", "work", "men", "win",
}

EXECUTABLE_EXT = {"exe", "msi", "scr", "bat", "dll", "jar", "apk", "ps1"}
ARCHIVE_EXT = {"zip", "rar", "7z"}
MACRO_DOC_EXT = {"docm", "xlsm"}
PDF_EXT = {"pdf"}
OFFICE_DOC_EXT = {"doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf"}

WHATSAPP_HOSTS = {"api.whatsapp.com", "wa.me", "web.whatsapp.com"}


def _ext_of_path(path: str) -> Optional[str]:
    seg = path.rsplit("/", 1)[-1]
    if "." in seg:
        ext = seg.rsplit(".", 1)[-1].lower()
        if ext:
            return ext
    return None


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False


def _has_credentials(netloc: str) -> bool:
    return "@" in netloc and ":" in netloc.split("@", 1)[0]


def _nonstd_port(scheme: str, port: Optional[int]) -> bool:
    if port is None:
        return False
    if scheme == "http" and port == 80:
        return False
    if scheme == "https" and port == 443:
        return False
    return True


def _contains_nested_url(value: str) -> bool:
    v = value.lower()
    if "http://" in v or "https://" in v:
        return True
    if "http%3a%2f%2f" in v or "https%3a%2f%2f" in v:
        return True
    return False


def _base64_decodes_to_url(value: str) -> bool:
    # Heurística simples para strings base64 que decodificam para URL
    s = value.strip()
    if len(s) < 12:
        return False
    # Remover padding incorreto não impede tentativa
    try:
        padded = s + "=" * ((4 - len(s) % 4) % 4)
        raw = base64.b64decode(padded, validate=False)
        txt = raw.decode("utf-8", errors="ignore").lower()
        return txt.startswith("http://") or txt.startswith("https://")
    except Exception:
        return False


def assess_url_risk(url: str, *, page: Optional[str] = None, origin: Optional[str] = None) -> Dict[str, Any]:
    """Aplica heurísticas leves e retorna tags, motivos e score.

    - page: URL da página de origem (para mixed-content).
    """
    tags: List[str] = []
    reasons: List[str] = []
    score = 0
    link_type: Optional[str] = None  # page | asset:image | asset:script | asset:style
    ownership: Optional[str] = None  # internal | external

    p = urlparse(url)
    host = (p.hostname or "").lower()
    netloc = p.netloc
    scheme = p.scheme.lower()
    port = p.port
    ext = _ext_of_path(p.path or "")
    # alvos/encoding de possíveis redirecionamentos em parâmetros
    target_url: Optional[str] = None
    encoding: Optional[str] = None

    # Ownership (quando origem é conhecida)
    try:
        if origin:
            ownership = "internal" if _same_site(url, origin, include_subdomains=True) else "external"
    except Exception:
        ownership = None

    # Tipagem por extensão (informativo)
    if ext in {"png", "jpg", "jpeg", "gif", "svg", "webp", "ico"}:
        link_type = "asset:image"
    elif ext in {"css"}:
        link_type = "asset:style"
    elif ext in {"js"}:
        link_type = "asset:script"

    # HTTP sem TLS
    if scheme == "http":
        tags.append("http-scheme")
        reasons.append("URL usa HTTP sem TLS")
        score += 1

    # IP literal
    if host and _is_ip_literal(host):
        tags.append("ip-literal")
        reasons.append("Host é um endereço IP literal")
        score += 3

    # Credenciais embutidas
    if _has_credentials(netloc):
        tags.append("credentials-in-url")
        reasons.append("URL contém usuário/senha no host")
        score += 5

    # Porta não padrão
    if _nonstd_port(scheme, port):
        tags.append("nonstd-port")
        reasons.append(f"Porta não padrão: {port}")
        score += 2

    # Punycode/IDN
    if "xn--" in host:
        tags.append("punycode-idn")
        reasons.append("Host contém punycode (IDN)")
        score += 3

    # TLD arriscado
    if "." in host:
        tld = host.rsplit(".", 1)[-1]
        if tld in RISKY_TLDS:
            tags.append("risky-tld")
            reasons.append(f"TLD potencialmente arriscado: .{tld}")
            score += 3

    # Shorteners
    if host in SHORTENERS:
        tags.append("shortener")
        reasons.append("Domínio de encurtador conhecido")
        score += 4

    # Webhooks
    for pat in WEBHOOK_PATTERNS:
        if pat in url:
            tags.append("webhook-endpoint")
            reasons.append("Padrão de webhook (ex.: Slack/Discord)")
            score += 6
            break

    # Paste sites
    if host in PASTE_SITES:
        tags.append("paste-site")
        reasons.append("Link para serviço de paste")
        score += 3

    # Extensões suspeitas
    if ext in EXECUTABLE_EXT:
        tags.append("executable")
        reasons.append(f"Extensão executável: .{ext}")
        score += 7
    elif ext in ARCHIVE_EXT:
        tags.append("archive")
        reasons.append(f"Arquivo compactado: .{ext}")
        score += 5
    elif ext in MACRO_DOC_EXT:
        tags.append("macro-doc")
        reasons.append(f"Documento com macros: .{ext}")
        score += 5
    elif ext in PDF_EXT:
        tags.append("document-pdf")
        reasons.append("Documento PDF")
        score += 1
    elif ext in OFFICE_DOC_EXT:
        tags.append("document-office")
        reasons.append(f"Documento Office/ODF: .{ext}")
        score += 2

    # Query params
    if p.query:
        params = parse_qsl(p.query, keep_blank_values=True)
        # open redirect hints
        redir_keys = {
            "redirect", "redirect_uri", "redirect_url", "return", "returnto",
            "url", "next", "target", "dest", "destination",
        }
        tracking_keys = {"gclid", "fbclid", "trk", "ref", "src"}
        pii_keys = {"email", "cpf", "cnpj", "phone", "token", "api_key", "key", "password", "secret"}
        nested = False
        b64 = False
        pii = False
        contact_phone_added = False
        for k, v in params:
            kl = (k or "").lower()
            vl = (v or "")
            # Tracking genérico (informativo)
            if kl.startswith("utm_") or kl in tracking_keys:
                if "tracking-param" not in tags:
                    tags.append("tracking-param")
                    reasons.append("Parâmetros de tracking na URL")
            if kl in redir_keys and _contains_nested_url(vl):
                nested = True
                # tenta decodificar percent-encoding
                try:
                    u_dec = unquote_plus(vl)
                except Exception:
                    u_dec = vl
                target_url = u_dec if u_dec.lower().startswith(("http://", "https://")) else target_url
                encoding = encoding or ("percent" if "%" in vl else "plain")
            if _contains_nested_url(vl):
                nested = True
                try:
                    u_dec = unquote_plus(vl)
                except Exception:
                    u_dec = vl
                if u_dec.lower().startswith(("http://", "https://")):
                    target_url = target_url or u_dec
                    encoding = encoding or ("percent" if "%" in vl else "plain")
            # base64 → URL
            vv = unquote_plus(vl)
            if _base64_decodes_to_url(vv):
                b64 = True
                try:
                    padded = vv + "=" * ((4 - len(vv) % 4) % 4)
                    raw = base64.b64decode(padded, validate=False)
                    txt = raw.decode("utf-8", errors="ignore")
                    if txt.lower().startswith(("http://", "https://")) and not target_url:
                        target_url = txt
                        encoding = encoding or "base64"
                except Exception:
                    pass
            if kl in pii_keys:
                if kl == "phone" and host in WHATSAPP_HOSTS:
                    if not contact_phone_added:
                        tags.append("contact-phone")
                        reasons.append("Parâmetro 'phone' em WhatsApp (contato intencional)")
                        contact_phone_added = True
                    # não marcar como PII
                else:
                    pii = True
        if nested:
            tags.append("param-redirect")
            reasons.append("Parâmetro contendo URL possivelmente redirecionada")
            score += 4
        if target_url:
            # marca contexto do alvo e se é externo
            try:
                external = _domain_of_url(target_url) != _domain_of_url(url)
            except Exception:
                external = None
            tag = "external-target" if external else "internal-target"
            if external is not None:
                tags.append(tag)
            reasons.append(f"Alvo de redirecionamento detectado: {target_url}")
        if encoding:
            tags.append(f"encoding:{encoding}")
        if b64:
            tags.append("base64-url")
            reasons.append("Parâmetro parece base64 que decodifica para URL")
            score += 5
        if pii:
            tags.append("pii/secret-in-url")
            reasons.append("Parâmetro com possível PII/segredo (email/token/chave)")
            score += 3

    # Mixed content (se tivermos contexto)
    if page and page.startswith("https://") and url.startswith("http://"):
        tags.append("mixed-content")
        reasons.append("Página HTTPS referenciando recurso HTTP")
        score += 2

    out: Dict[str, Any] = {
        "url": url,
        **({"page": page} if page else {}),
        "tags": tags,
        "reasons": reasons,
        "score": score,
    }
    out["link_type"] = link_type or "page"
    if ownership:
        out["ownership"] = ownership
    if target_url:
        out["target_url"] = target_url
        try:
            out["external_target"] = _domain_of_url(target_url) != _domain_of_url(url)
        except Exception:
            out["external_target"] = None
    if encoding:
        out["encoding"] = encoding
    # third-party-lib e third-party-js (informativos)
    try:
        path_l = (p.path or "").lower()
        if any(s in path_l for s in ["jquery", "bootstrap", "swiper", "owl", "fontawesome"]):
            out.setdefault("tags", []).append("third-party-lib")
            out.setdefault("reasons", []).append("Biblioteca de terceiros detectada por filename")
        if out.get("link_type") == "asset:script" and out.get("ownership") == "external":
            out.setdefault("tags", []).append("third-party-js")
            out.setdefault("reasons", []).append("Script de terceiro referenciado")
    except Exception:
        pass
    return out


def aggregate_risk(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_tag: Dict[str, int] = {}
    hi = mid = low = 0
    for it in items:
        for t in it.get("tags", []):
            by_tag[t] = by_tag.get(t, 0) + 1
        s = int(it.get("score", 0))
        if s >= 7:
            hi += 1
        elif s >= 3:
            mid += 1
        else:
            low += 1
    return {
        "total": len(items),
        "by_tag": by_tag,
        "risk_buckets": {"high": hi, "medium": mid, "low": low},
    }


def verify_param_redirect(url: str, *, session, timeout: int = 10) -> Dict[str, Any]:
    """Verifica via HEAD se um parâmetro de redirecionamento causa redirect externo.

    - Retorna dict com chaves: detected(bool), status(int|None), location(str|None)
    - Estratégia: substitui o primeiro parâmetro conhecido por um alvo de teste e
      faz HEAD com allow_redirects=False.
    """
    KNOWN_TARGET = "https://example.org/"
    p = urlparse(url)
    params = parse_qsl(p.query, keep_blank_values=True)
    redir_keys = [
        "redirect", "redirect_uri", "redirect_url", "return", "returnto",
        "url", "next", "target", "dest", "destination",
    ]
    if not params:
        return {"detected": False, "status": None, "location": None}
    # escolhe a primeira key conhecida presente
    key = next((k for (k, v) in params if k.lower() in redir_keys), None)
    if not key:
        return {"detected": False, "status": None, "location": None}
    new_params: List[Tuple[str, str]] = []
    for k, v in params:
        if k == key:
            new_params.append((k, KNOWN_TARGET))
        else:
            new_params.append((k, v))
    new_qs = urlencode(new_params, doseq=True)
    new_url = urlunparse((p.scheme, p.netloc, p.path, p.params, new_qs, p.fragment))
    try:
        resp = session.head(new_url, timeout=timeout, allow_redirects=False)
        status = getattr(resp, "status_code", None)
        loc = resp.headers.get("Location") if getattr(resp, "headers", None) else None
        if status and 300 <= int(status) < 400 and loc:
            abs_loc = urljoin(new_url, loc)
            try:
                is_external = _domain_of_url(abs_loc) != _domain_of_url(url)
            except Exception:
                is_external = None
            return {
                "detected": bool(is_external),
                "status": status,
                "location": abs_loc,
            }
        return {"detected": False, "status": status, "location": loc}
    except Exception:
        return {"detected": False, "status": None, "location": None}
