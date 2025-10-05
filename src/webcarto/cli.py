"""Coletor de URLs simples.

- Faz download de páginas com `requests` e extrai links com `BeautifulSoup`.
- Pode navegar (crawl) seguindo links internos até um limite de profundidade/páginas.
- Suporta modos de saída: lista simples, árvore por domínio (`--tree`) e árvore por página (`--page-tree`).
"""

import argparse
import configparser
import datetime
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urljoin, urlparse, urlunparse

from .crawler import Crawler, CrawlParams
from .html_utils import extract_links_extended, extract_links_ordered
from .http_utils import create_session
from .io_utils import read_file, save_output, save_risk_report
from .metrics import compute_result_metrics
from .reputation import (
    ReputationClient,
    build_reputation_metrics,
    consolidate_verdict,
    parse_ttl,
)
from .risk import aggregate_risk, assess_url_risk, verify_param_redirect
from .transforms import build_domain_tree
from .urls_utils import _normalize_url, _same_site

def crawl_site(
    start_url: str,
    *,
    max_pages: int = 200,
    max_depth: int = 2,
    include_external: bool = True,
    follow_external: bool = False,
    include_subdomains: bool = True,
    delay_seconds: float = 0.0,
    user_agent: str = "site-scraping-example/1.0",
    respect_robots: bool = True,
    timeout: int = 20,
    verbose: bool = False,
    retries: int = 2,
    retry_backoff: float = 0.3,
    log_path: Optional[str] = None,
    include_assets: bool = False,
    include_forms: bool = False,
) -> Tuple[List[str], Dict[str, Any]]:
    """Crawling a partir de `start_url`, retornando a lista de URLs coletadas."""
    crawler = Crawler(
        start_url,
        max_pages=max_pages,
        max_depth=max_depth,
        include_external=include_external,
        follow_external=follow_external,
        include_subdomains=include_subdomains,
        delay_seconds=delay_seconds,
        user_agent=user_agent,
        respect_robots=respect_robots,
        timeout=timeout,
        verbose=verbose,
        retries=retries,
        retry_backoff=retry_backoff,
        log_path=log_path,
        include_assets=include_assets,
        include_forms=include_forms,
    )
    return crawler.run_flat()


def crawl_site_grouped(
    start_url: str,
    *,
    max_pages: int = 200,
    max_depth: int = 2,
    include_external: bool = True,
    follow_external: bool = False,
    include_subdomains: bool = True,
    delay_seconds: float = 0.0,
    user_agent: str = "site-scraping-example/1.0",
    respect_robots: bool = True,
    timeout: int = 20,
    verbose: bool = False,
    retries: int = 2,
    retry_backoff: float = 0.3,
    log_path: Optional[str] = None,
    include_assets: bool = False,
    include_forms: bool = False,
) -> Tuple[Dict[str, List[str]], Dict[str, Any]]:
    crawler = Crawler(
        start_url,
        max_pages=max_pages,
        max_depth=max_depth,
        include_external=include_external,
        follow_external=follow_external,
        include_subdomains=include_subdomains,
        delay_seconds=delay_seconds,
        user_agent=user_agent,
        respect_robots=respect_robots,
        timeout=timeout,
        verbose=verbose,
        retries=retries,
        retry_backoff=retry_backoff,
        log_path=log_path,
        include_assets=include_assets,
        include_forms=include_forms,
    )
    return crawler.run_grouped()


def main() -> None:
    """CLI do coletor: parseia flags e executa conforme parâmetros."""
    parser = argparse.ArgumentParser(description="Coletor simples de URLs")
    parser.add_argument(
        "--url",
        default="https://quotes.toscrape.com/",
        help="URL inicial para coletar (ignorado com --input-file)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Usa HTML local de amostra em vez de acessar a web",
    )
    parser.add_argument(
        "--input-file",
        type=Path,
        help="Caminho para um arquivo HTML local (sobrepõe --offline)",
    )
    parser.add_argument(
        "--base-url",
        default="",
        help="Base para resolver links relativos ao usar --input-file/--offline",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("out/urls.json"),
        help="Arquivo de saída (json, csv ou txt)",
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        help="Carrega variáveis de ambiente de um arquivo (.env). Se omitido, tenta ./.env se existir",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Arquivo INI opcional com defaults (ex.: webcarto.ini) — seção [reputation]",
    )
    parser.add_argument(
        "--reputation-self-test",
        action="store_true",
        help="Executa um autoteste de providers de reputação e encerra",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Limita a prévia no console (0 = todos)",
    )
    # Opções do crawler
    parser.add_argument("--max-pages", type=int, default=200, help="Máximo de páginas para visitar")
    parser.add_argument("--max-depth", type=int, default=2, help="Profundidade máxima a partir da inicial")
    parser.add_argument("--all-domains", action="store_true", help="Permite SEGUIR links externos (por padrão só segue internos)")
    parser.add_argument("--only-internal", action="store_true", help="Lista apenas URLs do mesmo domínio no RESULTADO")
    parser.add_argument(
        "--no-subdomains",
        action="store_true",
        help="Não trata subdomínios como internos (exige host exato)",
    )
    parser.add_argument("--delay", type=float, default=0.0, help="Atraso entre requisições (segundos)")
    parser.add_argument(
        "--no-robots",
        action="store_true",
        help="Não verifica robots.txt (use com responsabilidade)",
    )
    parser.add_argument(
        "--tree",
        action="store_true",
        help="Saída em árvore por domínio/subdomínio",
    )
    parser.add_argument(
        "--page-tree",
        action="store_true",
        help="Saída em árvore por página (page -> [urls])",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Loga eventos do crawler (erros, robots, não-HTML)",
    )
    parser.add_argument(
        "--risk-report",
        type=Path,
        help="Gera relatório de risco (JSON) com tags/score por URL",
    )
    # Reputação (infra/CLI - ID 15)
    parser.add_argument("--verify-reputation", action="store_true", help="Consulta reputação externa (providers)")
    parser.add_argument("--reputation-providers", default="", help="Lista de providers (ex.: vt,gsb,urlhaus,otx)")
    parser.add_argument("--reputation-cache", default="out/reputation.json", help="Cache local de reputação (JSON)")
    parser.add_argument("--reputation-ttl", default="7d", help="TTL do cache (ex.: 7d, 24h, 3600s)")
    parser.add_argument("--reputation-concurrency", type=int, default=2, help="Consultas simultâneas aos provedores")
    parser.add_argument("--reputation-timeout", type=int, default=10, help="Timeout por requisição (s)")
    parser.add_argument("--reputation-include-query", action="store_true", help="Inclui querystring nas consultas (scrub padrão aplicado)")
    parser.add_argument("--reputation-scrub-params", default="utm_*,gclid,fbclid,trk,ref,src", help="Chaves de query para remover (csv)")
    parser.add_argument("--reputation-keys", default="", help="Chaves dos providers (ex.: vt=KEY,gsb=KEY,otx=KEY)")
    parser.add_argument("--reputation-strict", action="store_true", help="Erro se provider listado não tiver chave")
    parser.add_argument("--reputation-dry-run", action="store_true", help="Não consulta rede; usa apenas cache/stub")
    # Novas opções: coleta ampliada
    parser.add_argument(
        "--include-assets",
        action="store_true",
        help="Também coleta assets (img/src, script/src, link/href)",
    )
    parser.add_argument(
        "--include-forms",
        action="store_true",
        help="Também coleta ações de formulários (form/action)",
    )
    parser.add_argument(
        "--verify-redirects",
        action="store_true",
        help="Verifica online se parâmetros de redirecionamento geram 3xx externo",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="Total de tentativas por requisição HTTP (com backoff)",
    )
    parser.add_argument(
        "--retry-backoff",
        type=float,
        default=0.3,
        help="Fator de backoff exponencial entre tentativas HTTP",
    )
    parser.add_argument(
        "--log",
        type=Path,
        help="Persistir logs verbosos em arquivo (ex.: out/crawl.log)",
    )
    args = parser.parse_args()

    # Carregar .env (ENV) — se explicitado ou se ./.env existir
    def load_env_file(p: Path) -> None:
        try:
            if not p.exists():
                return
            for line in p.read_text(encoding="utf-8").splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if "=" in s:
                    k, v = s.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip('"').strip("'")
                    os.environ.setdefault(k, v)
        except Exception:
            pass

    if args.env_file:
        load_env_file(args.env_file)
    else:
        default_env = Path(".env")
        if default_env.exists():
            load_env_file(default_env)

    # Carregar config INI (defaults) — somente reputação nesta fase
    cfg = configparser.ConfigParser()
    cfg_path: Optional[Path] = None
    if args.config and args.config.exists():
        cfg_path = args.config
    elif Path("webcarto.ini").exists():
        cfg_path = Path("webcarto.ini")
    if cfg_path:
        try:
            cfg.read(cfg_path, encoding="utf-8")
        except Exception:
            pass

    def cfg_get(section: str, key: str, default: Optional[str] = None) -> Optional[str]:
        try:
            return cfg.get(section, key)
        except Exception:
            return default

    # Helper para mesclar config→args quando o valor em args é o default
    def merge_arg(cur, default, cfg_val, cast=None):
        if cfg_val is None:
            return cur
        if cur == default:
            try:
                return cast(cfg_val) if cast else cfg_val
            except Exception:
                return cur
        return cur

    # Self-test de reputação (executa cedo e encerra)
    if args.reputation_self_test:
        prov_cfg = cfg_get("reputation", "providers")
        cache_cfg = cfg_get("reputation", "cache")
        ttl_cfg = cfg_get("reputation", "ttl")
        conc_cfg = cfg_get("reputation", "concurrency")
        to_cfg = cfg_get("reputation", "timeout")
        incl_q_cfg = cfg_get("reputation", "include_query")
        scrub_cfg = cfg_get("reputation", "scrub_params")
        keys_cfg = cfg_get("reputation", "keys")
        providers_list = [p.strip() for p in args.reputation_providers.split(",") if p.strip()] or (
            [p.strip() for p in (prov_cfg or "").split(",") if p.strip()] or None
        )
        ttl_s = parse_ttl(args.reputation_ttl if args.reputation_ttl != "7d" or not ttl_cfg else ttl_cfg)
        cache_path = merge_arg(args.reputation_cache, "out/reputation.json", cache_cfg)
        rep_conc = merge_arg(args.reputation_concurrency, 2, conc_cfg, int)
        rep_timeout = merge_arg(args.reputation_timeout, 10, to_cfg, int)
        include_query = args.reputation_include_query or (str(incl_q_cfg).lower() == "true")
        scrub_params = [s.strip() for s in (args.reputation_scrub_params or (scrub_cfg or "")).split(",") if s.strip()]
        keys_map = {}
        if args.reputation_keys:
            for part in args.reputation_keys.split(","):
                if "=" in part:
                    k, v = part.split("=", 1)
                    keys_map[k.strip()] = v.strip()
        elif keys_cfg:
            for part in keys_cfg.split(","):
                if "=" in part:
                    k, v = part.split("=", 1)
                    keys_map[k.strip()] = v.strip()
        rep = ReputationClient(
            providers=providers_list,
            keys=keys_map or None,
            cache_path=str(cache_path),
            ttl_seconds=ttl_s,
            include_query=include_query,
            scrub_params=scrub_params,
            concurrency=int(rep_conc),
            timeout=int(rep_timeout),
            strict=args.reputation_strict,
            dry_run=args.reputation_dry_run,
            verbose=args.verbose,
        )
        result = rep.self_test()
        print(json.dumps({"reputation_self_test": result}, ensure_ascii=False, indent=2))
        return

    if args.input_file and not args.input_file.exists():
        raise SystemExit(f"Input file not found: {args.input_file}")
    # Somente fluxo de URLs (sem modo de "quotes")
    crawl_stats: Dict[str, Any] = {}
    if args.input_file:
        html = read_file(args.input_file)
        base = args.base_url or args.url or ""
        source = str(args.input_file)
        links_data = extract_links_extended(
            html,
            base,
            include_assets=args.include_assets,
            include_forms=args.include_forms,
        )
        urls = links_data["ordered_all"]
    elif args.offline:
        sample = Path("data/sample_links.html")
        if not sample.exists():
            raise SystemExit(
                "Offline sample not found at data/sample_links.html. "
                "Provide --input-file or run online without --offline."
            )
        html = read_file(sample)
        base = args.base_url or args.url or ""
        source = str(sample)
        links_data = extract_links_extended(
            html,
            base,
            include_assets=args.include_assets,
            include_forms=args.include_forms,
        )
        urls = links_data["ordered_all"]
    else:
        source = args.url
        # Evita crawl duplicado quando --page-tree online (o agrupado já fará o crawl)
        if args.page_tree:
            urls = []
            crawl_stats = {}
        else:
            urls, crawl_stats = crawl_site(
                args.url,
                max_pages=args.max_pages,
                max_depth=args.max_depth,
                include_external=not args.only_internal,
                follow_external=args.all_domains,
                include_subdomains=not args.no_subdomains,
                delay_seconds=args.delay,
                respect_robots=not args.no_robots,
                verbose=args.verbose,
                retries=args.retries,
                retry_backoff=args.retry_backoff,
                log_path=str(args.log) if args.log else None,
                include_assets=args.include_assets,
                include_forms=args.include_forms,
            )

    # Filtro opcional para modos offline/local quando --only-internal estiver ativo
    if args.only_internal:
        origin = None
        if args.input_file or args.offline:
            origin = _normalize_url(base) if base else None
        else:
            origin = _normalize_url(args.url)
        if origin:
            urls = [
                u for u in urls
                if _same_site(u, origin, include_subdomains=not args.no_subdomains)
            ]

    fmt = args.out.suffix.lower().lstrip(".") or "json"
    if args.page_tree:
        if source.startswith("http"):
            grouped, crawl_stats = crawl_site_grouped(
                args.url,
                max_pages=args.max_pages,
                max_depth=args.max_depth,
                include_external=not args.only_internal,
                follow_external=args.all_domains,
                include_subdomains=not args.no_subdomains,
                delay_seconds=args.delay,
                respect_robots=not args.no_robots,
                verbose=args.verbose,
                retries=args.retries,
                retry_backoff=args.retry_backoff,
                log_path=str(args.log) if args.log else None,
                include_assets=args.include_assets,
                include_forms=args.include_forms,
            )
        else:
            # Offline/local: trata como um único "contexto de página"
            parent = _normalize_url(base) if (args.base_url or args.url) else (Path(args.input_file).resolve().as_uri() if args.input_file else str(source))
            grouped = {parent or str(source): urls}
        # Prévia similar ao antigo --grouped
        keys = list(grouped.keys())
        n_pages = len(keys)
        n_preview = n_pages if args.limit in (None, 0) else min(args.limit, n_pages)
        for i, page in enumerate(sorted(keys)[:n_preview], start=1):
            print(f"[{i:02d}] {page}")
            for j, u in enumerate(grouped[page][:5], start=1):
                print(f"   - {u}")
        # Risk report (por página)
        if args.risk_report:
            risk_items = []
            for page, lst in grouped.items():
                for u in lst:
                    # origem estimada: args.url (online) ou base (offline)
                    origin = _normalize_url(args.url) if str(source).startswith("http") else (_normalize_url(base) if base else None)
                    risk_items.append(assess_url_risk(u, page=page, origin=origin))
            # reputação (infra ID 15/17): consulta e incorpora no payload
            if args.verify_reputation:
                # Config defaults
                prov_cfg = cfg_get("reputation", "providers")
                cache_cfg = cfg_get("reputation", "cache")
                ttl_cfg = cfg_get("reputation", "ttl")
                conc_cfg = cfg_get("reputation", "concurrency")
                to_cfg = cfg_get("reputation", "timeout")
                incl_q_cfg = cfg_get("reputation", "include_query")
                scrub_cfg = cfg_get("reputation", "scrub_params")
                keys_cfg = cfg_get("reputation", "keys")
                # Mesclar
                providers_list = [p.strip() for p in args.reputation_providers.split(",") if p.strip()] or (
                    [p.strip() for p in (prov_cfg or "").split(",") if p.strip()] or None
                )
                ttl_s = parse_ttl(args.reputation_ttl if args.reputation_ttl != "7d" or not ttl_cfg else ttl_cfg)
                cache_path = merge_arg(args.reputation_cache, "out/reputation.json", cache_cfg)
                rep_conc = merge_arg(args.reputation_concurrency, 2, conc_cfg, int)
                rep_timeout = merge_arg(args.reputation_timeout, 10, to_cfg, int)
                include_query = args.reputation_include_query or (str(incl_q_cfg).lower() == "true")
                scrub_params = [s.strip() for s in (args.reputation_scrub_params or (scrub_cfg or "")).split(",") if s.strip()]
                keys_map = {}
                if args.reputation_keys:
                    for part in args.reputation_keys.split(","):
                        if "=" in part:
                            k, v = part.split("=", 1)
                            keys_map[k.strip()] = v.strip()
                elif keys_cfg:
                    for part in keys_cfg.split(","):
                        if "=" in part:
                            k, v = part.split("=", 1)
                            keys_map[k.strip()] = v.strip()
                rep = ReputationClient(
                    providers=providers_list,
                    keys=keys_map or None,
                    cache_path=str(cache_path),
                    ttl_seconds=ttl_s,
                    include_query=include_query,
                    scrub_params=scrub_params,
                    concurrency=int(rep_conc),
                    timeout=int(rep_timeout),
                    strict=args.reputation_strict,
                    dry_run=args.reputation_dry_run,
                    verbose=args.verbose,
                )
                rep_results = rep.check_urls({it["url"] for it in risk_items if it.get("url")})
                # incorporar reputação nos itens (ID 17)
                for it in risk_items:
                    u = it.get("url")
                    if not u:
                        continue
                    pdata = rep_results.get(u) or {}
                    if pdata:
                        it["reputation"] = pdata
                        final_v = consolidate_verdict(pdata)
                        # tags/score
                        tag = f"reputation:{final_v}"
                        it.setdefault("tags", []).append(tag)
                        if final_v == "malicious":
                            it["score"] = int(it.get("score", 0)) + 6
                        elif final_v == "suspicious":
                            it["score"] = int(it.get("score", 0)) + 3
                rep_metrics = build_reputation_metrics(rep_results)
            # reputação (infra ID 15): consulta sem alterar o payload (ID 17 fará integração)
            if args.verify_reputation:
                keys_map = {}
                if args.reputation_keys:
                    for part in args.reputation_keys.split(","):
                        if "=" in part:
                            k, v = part.split("=", 1)
                            keys_map[k.strip()] = v.strip()
                providers_list = [p.strip() for p in args.reputation_providers.split(",") if p.strip()] or None
                ttl_s = parse_ttl(args.reputation_ttl)
                scrub_params = [s.strip() for s in (args.reputation_scrub_params or "").split(",") if s.strip()]
                rep = ReputationClient(
                    providers=providers_list,
                    keys=keys_map,
                    cache_path=str(args.reputation_cache),
                    ttl_seconds=ttl_s,
                    include_query=args.reputation_include_query,
                    scrub_params=scrub_params,
                    concurrency=args.reputation_concurrency,
                    timeout=args.reputation_timeout,
                    strict=args.reputation_strict,
                    dry_run=args.reputation_dry_run,
                    verbose=args.verbose,
                )
                _ = rep.check_urls({it["url"] for it in risk_items if it.get("url")})
            # verificação opcional de redirects (online)
            if args.verify_redirects:
                sess = create_session(retries=args.retries, backoff_factor=args.retry_backoff)
                for it in risk_items:
                    if "param-redirect" in it.get("tags", []):
                        vr = verify_param_redirect(it["url"], session=sess)
                        if vr.get("detected"):
                            it.setdefault("tags", []).append("server-redirect-detected")
                            it.setdefault("reasons", []).append("Redirecionamento servidor confirmado (externo)")
                            it["redirect_status"] = vr.get("status")
                            it["redirect_location"] = vr.get("location")
                            try:
                                it["score"] = int(it.get("score", 0)) + 3
                            except Exception:
                                it["score"] = it.get("score", 0)
            risk_metrics = aggregate_risk(risk_items)
            if args.verify_reputation:
                risk_metrics.update(rep_metrics)
            meta_r = {"source": source, "params": {"mode": "page-tree"}}
            save_risk_report(risk_items, args.risk_report, meta=meta_r, metrics=risk_metrics)
            print(f"[risk] Report saved -> {args.risk_report}")
        origin = _normalize_url(base) if (args.input_file or args.offline) else _normalize_url(args.url)
        flat_urls: List[str] = []
        for v in grouped.values():
            flat_urls.extend(v)
        metrics = compute_result_metrics(flat_urls, origin, include_subdomains=not args.no_subdomains, pages_count=len(grouped))
        if crawl_stats:
            metrics.update(crawl_stats)
        meta = {
            "source": source,
            "params": {
                "max_pages": args.max_pages,
                "max_depth": args.max_depth,
                "include_external": not args.only_internal,
                "follow_external": args.all_domains,
                "include_subdomains": not args.no_subdomains,
            },
        }
        save_output(grouped, args.out, fmt=fmt, meta=meta, metrics=metrics)
        total_links = sum(len(v) for v in grouped.values())
        print(f"\nCollected {total_links} URLs across {len(grouped)} pages from {source} -> {args.out}")
    elif args.tree:
        # Monta árvore: domain -> host -> [urls]
        tree: Dict[str, Dict[str, List[str]]] = build_domain_tree(urls)
        # Prévia limitada por --limit: mostra nós de domínio
        domains = sorted(tree.keys())
        n_preview = len(domains) if args.limit in (None, 0) else min(args.limit, len(domains))
        for i, dom in enumerate(domains[:n_preview], start=1):
            print(f"[{i:02d}] {dom}")
            hosts = sorted(tree[dom].keys())
            for h in hosts[:3]:
                print(f"   - {h}")
        if args.risk_report:
            # Sem contexto de página, mas ainda útil
            origin = _normalize_url(base) if (args.input_file or args.offline) else _normalize_url(args.url)
            risk_items = [assess_url_risk(u, origin=origin) for u in urls]
            if args.verify_reputation:
                prov_cfg = cfg_get("reputation", "providers")
                cache_cfg = cfg_get("reputation", "cache")
                ttl_cfg = cfg_get("reputation", "ttl")
                conc_cfg = cfg_get("reputation", "concurrency")
                to_cfg = cfg_get("reputation", "timeout")
                incl_q_cfg = cfg_get("reputation", "include_query")
                scrub_cfg = cfg_get("reputation", "scrub_params")
                keys_cfg = cfg_get("reputation", "keys")
                providers_list = [p.strip() for p in args.reputation_providers.split(",") if p.strip()] or (
                    [p.strip() for p in (prov_cfg or "").split(",") if p.strip()] or None
                )
                ttl_s = parse_ttl(args.reputation_ttl if args.reputation_ttl != "7d" or not ttl_cfg else ttl_cfg)
                cache_path = merge_arg(args.reputation_cache, "out/reputation.json", cache_cfg)
                rep_conc = merge_arg(args.reputation_concurrency, 2, conc_cfg, int)
                rep_timeout = merge_arg(args.reputation_timeout, 10, to_cfg, int)
                include_query = args.reputation_include_query or (str(incl_q_cfg).lower() == "true")
                scrub_params = [s.strip() for s in (args.reputation_scrub_params or (scrub_cfg or "")).split(",") if s.strip()]
                keys_map = {}
                if args.reputation_keys:
                    for part in args.reputation_keys.split(","):
                        if "=" in part:
                            k, v = part.split("=", 1)
                            keys_map[k.strip()] = v.strip()
                elif keys_cfg:
                    for part in keys_cfg.split(","):
                        if "=" in part:
                            k, v = part.split("=", 1)
                            keys_map[k.strip()] = v.strip()
                rep = ReputationClient(
                    providers=providers_list,
                    keys=keys_map or None,
                    cache_path=str(cache_path),
                    ttl_seconds=ttl_s,
                    include_query=include_query,
                    scrub_params=scrub_params,
                    concurrency=int(rep_conc),
                    timeout=int(rep_timeout),
                    strict=args.reputation_strict,
                    dry_run=args.reputation_dry_run,
                    verbose=args.verbose,
                )
                rep_results = rep.check_urls({it["url"] for it in risk_items if it.get("url")})
                for it in risk_items:
                    u = it.get("url")
                    if not u:
                        continue
                    pdata = rep_results.get(u) or {}
                    if pdata:
                        it["reputation"] = pdata
                        final_v = consolidate_verdict(pdata)
                        it.setdefault("tags", []).append(f"reputation:{final_v}")
                        if final_v == "malicious":
                            it["score"] = int(it.get("score", 0)) + 6
                        elif final_v == "suspicious":
                            it["score"] = int(it.get("score", 0)) + 3
                rep_metrics = build_reputation_metrics(rep_results)
            if args.verify_reputation:
                keys_map = {}
                if args.reputation_keys:
                    for part in args.reputation_keys.split(","):
                        if "=" in part:
                            k, v = part.split("=", 1)
                            keys_map[k.strip()] = v.strip()
                providers_list = [p.strip() for p in args.reputation_providers.split(",") if p.strip()] or None
                ttl_s = parse_ttl(args.reputation_ttl)
                scrub_params = [s.strip() for s in (args.reputation_scrub_params or "").split(",") if s.strip()]
                rep = ReputationClient(
                    providers=providers_list,
                    keys=keys_map,
                    cache_path=str(args.reputation_cache),
                    ttl_seconds=ttl_s,
                    include_query=args.reputation_include_query,
                    scrub_params=scrub_params,
                    concurrency=args.reputation_concurrency,
                    timeout=args.reputation_timeout,
                    strict=args.reputation_strict,
                    dry_run=args.reputation_dry_run,
                    verbose=args.verbose,
                )
                _ = rep.check_urls({it["url"] for it in risk_items if it.get("url")})
            if args.verify_redirects:
                sess = create_session(retries=args.retries, backoff_factor=args.retry_backoff)
                for it in risk_items:
                    if "param-redirect" in it.get("tags", []):
                        vr = verify_param_redirect(it["url"], session=sess)
                        if vr.get("detected"):
                            it.setdefault("tags", []).append("server-redirect-detected")
                            it.setdefault("reasons", []).append("Redirecionamento servidor confirmado (externo)")
                            it["redirect_status"] = vr.get("status")
                            it["redirect_location"] = vr.get("location")
                            try:
                                it["score"] = int(it.get("score", 0)) + 3
                            except Exception:
                                it["score"] = it.get("score", 0)
            risk_metrics = aggregate_risk(risk_items)
            if args.verify_reputation:
                risk_metrics.update(rep_metrics)
            meta_r = {"source": source, "params": {"mode": "tree"}}
            save_risk_report(risk_items, args.risk_report, meta=meta_r, metrics=risk_metrics)
            print(f"[risk] Report saved -> {args.risk_report}")
        origin = _normalize_url(base) if (args.input_file or args.offline) else _normalize_url(args.url)
        metrics = compute_result_metrics(urls, origin, include_subdomains=not args.no_subdomains)
        if crawl_stats:
            metrics.update(crawl_stats)
        meta = {
            "source": source,
            "params": {
                "max_pages": args.max_pages,
                "max_depth": args.max_depth,
                "include_external": not args.only_internal,
                "follow_external": args.all_domains,
                "include_subdomains": not args.no_subdomains,
            },
        }
        save_output(tree, args.out, fmt=fmt, meta=meta, metrics=metrics)
        total_links = sum(len(v) for hosts in tree.values() for v in hosts.values())
        print(f"\nCollected {total_links} URLs across {len(tree)} domains from {source} -> {args.out}")
    else:
        n_preview = len(urls) if args.limit in (None, 0) else min(args.limit, len(urls))
        for i, u in enumerate(urls[:n_preview], start=1):
            print(f"{i:02d}. {u}")
        if args.risk_report:
            origin = _normalize_url(base) if (args.input_file or args.offline) else _normalize_url(args.url)
            risk_items = [assess_url_risk(u, origin=origin) for u in urls]
            if args.verify_reputation:
                prov_cfg = cfg_get("reputation", "providers")
                cache_cfg = cfg_get("reputation", "cache")
                ttl_cfg = cfg_get("reputation", "ttl")
                conc_cfg = cfg_get("reputation", "concurrency")
                to_cfg = cfg_get("reputation", "timeout")
                incl_q_cfg = cfg_get("reputation", "include_query")
                scrub_cfg = cfg_get("reputation", "scrub_params")
                keys_cfg = cfg_get("reputation", "keys")
                providers_list = [p.strip() for p in args.reputation_providers.split(",") if p.strip()] or (
                    [p.strip() for p in (prov_cfg or "").split(",") if p.strip()] or None
                )
                ttl_s = parse_ttl(args.reputation_ttl if args.reputation_ttl != "7d" or not ttl_cfg else ttl_cfg)
                cache_path = merge_arg(args.reputation_cache, "out/reputation.json", cache_cfg)
                rep_conc = merge_arg(args.reputation_concurrency, 2, conc_cfg, int)
                rep_timeout = merge_arg(args.reputation_timeout, 10, to_cfg, int)
                include_query = args.reputation_include_query or (str(incl_q_cfg).lower() == "true")
                scrub_params = [s.strip() for s in (args.reputation_scrub_params or (scrub_cfg or "")).split(",") if s.strip()]
                keys_map = {}
                if args.reputation_keys:
                    for part in args.reputation_keys.split(","):
                        if "=" in part:
                            k, v = part.split("=", 1)
                            keys_map[k.strip()] = v.strip()
                elif keys_cfg:
                    for part in keys_cfg.split(","):
                        if "=" in part:
                            k, v = part.split("=", 1)
                            keys_map[k.strip()] = v.strip()
                rep = ReputationClient(
                    providers=providers_list,
                    keys=keys_map or None,
                    cache_path=str(cache_path),
                    ttl_seconds=ttl_s,
                    include_query=include_query,
                    scrub_params=scrub_params,
                    concurrency=int(rep_conc),
                    timeout=int(rep_timeout),
                    strict=args.reputation_strict,
                    dry_run=args.reputation_dry_run,
                    verbose=args.verbose,
                )
                rep_results = rep.check_urls({it["url"] for it in risk_items if it.get("url")})
                for it in risk_items:
                    u = it.get("url")
                    if not u:
                        continue
                    pdata = rep_results.get(u) or {}
                    if pdata:
                        it["reputation"] = pdata
                        final_v = consolidate_verdict(pdata)
                        it.setdefault("tags", []).append(f"reputation:{final_v}")
                        if final_v == "malicious":
                            it["score"] = int(it.get("score", 0)) + 6
                        elif final_v == "suspicious":
                            it["score"] = int(it.get("score", 0)) + 3
                rep_metrics = build_reputation_metrics(rep_results)
            if args.verify_reputation:
                keys_map = {}
                if args.reputation_keys:
                    for part in args.reputation_keys.split(","):
                        if "=" in part:
                            k, v = part.split("=", 1)
                            keys_map[k.strip()] = v.strip()
                providers_list = [p.strip() for p in args.reputation_providers.split(",") if p.strip()] or None
                ttl_s = parse_ttl(args.reputation_ttl)
                scrub_params = [s.strip() for s in (args.reputation_scrub_params or "").split(",") if s.strip()]
                rep = ReputationClient(
                    providers=providers_list,
                    keys=keys_map,
                    cache_path=str(args.reputation_cache),
                    ttl_seconds=ttl_s,
                    include_query=args.reputation_include_query,
                    scrub_params=scrub_params,
                    concurrency=args.reputation_concurrency,
                    timeout=args.reputation_timeout,
                    strict=args.reputation_strict,
                    dry_run=args.reputation_dry_run,
                    verbose=args.verbose,
                )
                _ = rep.check_urls({it["url"] for it in risk_items if it.get("url")})
            if args.verify_redirects:
                sess = create_session(retries=args.retries, backoff_factor=args.retry_backoff)
                for it in risk_items:
                    if "param-redirect" in it.get("tags", []):
                        vr = verify_param_redirect(it["url"], session=sess)
                        if vr.get("detected"):
                            it.setdefault("tags", []).append("server-redirect-detected")
                            it.setdefault("reasons", []).append("Redirecionamento servidor confirmado (externo)")
                            it["redirect_status"] = vr.get("status")
                            it["redirect_location"] = vr.get("location")
                            try:
                                it["score"] = int(it.get("score", 0)) + 3
                            except Exception:
                                it["score"] = it.get("score", 0)
            risk_metrics = aggregate_risk(risk_items)
            if args.verify_reputation:
                risk_metrics.update(rep_metrics)
            meta_r = {"source": source, "params": {"mode": "list"}}
            save_risk_report(risk_items, args.risk_report, meta=meta_r, metrics=risk_metrics)
            print(f"[risk] Report saved -> {args.risk_report}")
        origin = _normalize_url(base) if (args.input_file or args.offline) else _normalize_url(args.url)
        metrics = compute_result_metrics(urls, origin, include_subdomains=not args.no_subdomains)
        if crawl_stats:
            metrics.update(crawl_stats)
        meta = {
            "source": source,
            "params": {
                "max_pages": args.max_pages,
                "max_depth": args.max_depth,
                "include_external": not args.only_internal,
                "follow_external": args.all_domains,
                "include_subdomains": not args.no_subdomains,
            },
        }
        save_output(urls, args.out, fmt=fmt, meta=meta, metrics=metrics)
        print(f"\nCollected {len(urls)} URLs from {source} -> {args.out}")



# Permite rodar como script mesmo se importado em alguns ambientes
if __name__ == "__main__":
    main()
