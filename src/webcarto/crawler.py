from typing import Any, Dict, List, Optional, Set, Tuple
from collections import deque
from dataclasses import dataclass
from urllib.parse import urlparse
import time

from .urls_utils import strip_www, _normalize_url, _same_site
from .html_utils import extract_links_extended, extract_links_ordered
from .http_utils import fetch_page, is_html_response, load_robots, create_session
from .metrics import CrawlMetrics

try:  # pragma: no cover
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None  # type: ignore


@dataclass(frozen=True)
class CrawlParams:
    max_pages: int = 200
    max_depth: int = 2
    include_external: bool = True
    follow_external: bool = False
    include_subdomains: bool = True
    delay_seconds: float = 0.0
    user_agent: str = "site-scraping-example/1.0"
    respect_robots: bool = True
    timeout: int = 20
    verbose: bool = False
    retries: int = 2
    retry_backoff: float = 0.3
    log_path: Optional[str] = None
    include_assets: bool = False
    include_forms: bool = False


class Crawler:
    def __init__(
        self,
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
    ) -> None:
        if requests is None:
            raise RuntimeError("'requests' is not installed. Run: pip install -r requirements.txt")
        self.start_url_n = _normalize_url(start_url)
        if not self.start_url_n:
            raise ValueError("Invalid start URL")
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.include_external = include_external
        self.follow_external = follow_external
        self.include_subdomains = include_subdomains
        self.delay_seconds = delay_seconds
        self.user_agent = user_agent
        self.timeout = timeout
        self.verbose = verbose
        self.headers = {"User-Agent": user_agent}
        self.retries = retries
        self.retry_backoff = retry_backoff
        self.log_path = log_path
        self.include_assets = include_assets
        self.include_forms = include_forms
        self.queue: deque[Tuple[str, int]] = deque([(self.start_url_n, 0)])
        self.visited_pages: Set[str] = set()
        self.metrics = CrawlMetrics()
        self.rp = load_robots(self.start_url_n, user_agent) if respect_robots else None
        self.session = create_session(retries=self.retries, backoff_factor=self.retry_backoff)

        pu = urlparse(self.start_url_n)
        origin_host = (pu.hostname or "").lower()
        self.base_host = strip_www(origin_host)

    @classmethod
    def from_params(cls, start_url: str, params: CrawlParams) -> "Crawler":
        return cls(
            start_url,
            max_pages=params.max_pages,
            max_depth=params.max_depth,
            include_external=params.include_external,
            follow_external=params.follow_external,
            include_subdomains=params.include_subdomains,
            delay_seconds=params.delay_seconds,
            user_agent=params.user_agent,
            respect_robots=params.respect_robots,
            timeout=params.timeout,
            verbose=params.verbose,
            retries=params.retries,
            retry_backoff=params.retry_backoff,
            log_path=params.log_path,
            include_assets=params.include_assets,
            include_forms=params.include_forms,
        )

    def _can_fetch(self, url: str) -> bool:
        if not self.rp:
            return True
        return self.rp.can_fetch(self.user_agent, url)

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(msg)
        if self.log_path:
            try:
                with open(self.log_path, "a", encoding="utf-8") as fh:
                    fh.write(msg + "\n")
            except Exception:
                # Evita quebrar o fluxo do crawler por erro de IO
                pass

    def _group_links(self, links: List[str]) -> Tuple[List[str], List[str], List[str]]:
        same_host_group: List[str] = []
        subdomain_group: List[str] = []
        external_group: List[str] = []
        for link in links:
            lh = (urlparse(link).hostname or "").lower()
            lh_s = strip_www(lh)
            if lh_s == self.base_host:
                same_host_group.append(link)
            elif (not self.include_subdomains) and lh_s != self.base_host:
                external_group.append(link)
            elif self.include_subdomains and (lh_s.endswith("." + self.base_host) or self.base_host.endswith("." + lh_s)):
                subdomain_group.append(link)
            else:
                external_group.append(link)
        return same_host_group, subdomain_group, external_group

    def run_flat(self) -> Tuple[List[str], Dict[str, Any]]:
        discovered_links: Set[str] = set()
        while self.queue and len(self.visited_pages) < self.max_pages:
            url, depth = self.queue.popleft()
            if url in self.visited_pages:
                continue
            if self.rp and not self._can_fetch(url):
                self.metrics.inc_robot_block()
                self._log(f"[robots] blocked: {url}")
                continue
            if self.verbose:
                seq = len(self.visited_pages) + 1
                self._log(f"[visit#{seq}] depth={depth} {url}")

            resp, elapsed_ms, exc = fetch_page(self.session, url, headers=self.headers, timeout=self.timeout)
            if exc is not None:
                self.metrics.record_request(getattr(getattr(exc, 'response', None), 'status_code', None), elapsed_ms)
                self.metrics.record_exception(exc)
                code = getattr(getattr(exc, 'response', None), 'status_code', None)
                code_s = str(code) if code is not None else "-"
                self._log(f"[error] {code_s} {elapsed_ms:.0f}ms {url} -> {type(exc).__name__}")
                self.visited_pages.add(url)
                continue

            self.metrics.record_request(getattr(resp, 'status_code', None), elapsed_ms)
            if not is_html_response(resp):
                self.metrics.mark_non_html()
                ct = (resp.headers.get("Content-Type") or "-")
                code_s = str(getattr(resp, 'status_code', '-'))
                self._log(f"[skip] non-HTML {code_s} {elapsed_ms:.0f}ms {url} ({ct})")
                self.visited_pages.add(url)
                continue

            html = resp.text
            links_data = extract_links_extended(
                html,
                resp.url,
                include_assets=self.include_assets,
                include_forms=self.include_forms,
            )
            links = links_data["ordered_all"]
            links_a = links_data["links_a"]
            code_s = str(getattr(resp, 'status_code', '-'))
            self._log(f"[ok] {code_s} {elapsed_ms:.0f}ms {url} ({len(links)} links)")

            same_host, subdomains, externals = self._group_links(links)
            for link in same_host + subdomains + externals:
                if _same_site(link, self.start_url_n, include_subdomains=self.include_subdomains) or self.include_external:
                    discovered_links.add(link)
                # Enfileira apenas anchors
                if link in links_a and depth + 1 <= self.max_depth:
                    if _same_site(link, self.start_url_n, include_subdomains=self.include_subdomains) or self.follow_external:
                        if link not in self.visited_pages:
                            self.queue.append((link, depth + 1))
                            self._log(f"[enqueue] depth={depth+1} {link}")

            self.visited_pages.add(url)
            self.metrics.mark_success()
            if self.delay_seconds > 0:
                time.sleep(self.delay_seconds)

        discovered_links.add(self.start_url_n)
        self.metrics.finalize(len(self.visited_pages))
        return sorted(discovered_links), self.metrics.as_dict()

    def run_grouped(self) -> Tuple[Dict[str, List[str]], Dict[str, Any]]:
        grouped: Dict[str, Set[str]] = {}
        while self.queue and len(self.visited_pages) < self.max_pages:
            url, depth = self.queue.popleft()
            if url in self.visited_pages:
                continue
            if self.rp and not self._can_fetch(url):
                self.metrics.inc_robot_block()
                self._log(f"[robots] blocked: {url}")
                continue
            if self.verbose:
                seq = len(self.visited_pages) + 1
                self._log(f"[visit#{seq}] depth={depth} {url}")

            resp, elapsed_ms, exc = fetch_page(self.session, url, headers=self.headers, timeout=self.timeout)
            if exc is not None:
                self.metrics.record_request(getattr(getattr(exc, 'response', None), 'status_code', None), elapsed_ms)
                self.metrics.record_exception(exc)
                code = getattr(getattr(exc, 'response', None), 'status_code', None)
                code_s = str(code) if code is not None else "-"
                self._log(f"[error] {code_s} {elapsed_ms:.0f}ms {url} -> {type(exc).__name__}")
                self.visited_pages.add(url)
                continue

            self.metrics.record_request(getattr(resp, 'status_code', None), elapsed_ms)
            if not is_html_response(resp):
                self.metrics.mark_non_html()
                ct = (resp.headers.get("Content-Type") or "-")
                code_s = str(getattr(resp, 'status_code', '-'))
                self._log(f"[skip] non-HTML {code_s} {elapsed_ms:.0f}ms {url} ({ct})")
                self.visited_pages.add(url)
                continue

            page_url = _normalize_url(resp.url) or url
            html = resp.text
            links_data = extract_links_extended(
                html,
                page_url,
                include_assets=self.include_assets,
                include_forms=self.include_forms,
            )
            links = links_data["ordered_all"]
            links_a = links_data["links_a"]
            code_s = str(getattr(resp, 'status_code', '-'))
            self._log(f"[ok] {code_s} {elapsed_ms:.0f}ms {url} ({len(links)} links)")

            same_host, subdomains, externals = self._group_links(links)
            ordered = same_host + subdomains + externals
            filtered: Set[str] = set()
            for link in ordered:
                if _same_site(link, self.start_url_n, include_subdomains=self.include_subdomains) or self.include_external:
                    filtered.add(link)
                if link in links_a and depth + 1 <= self.max_depth:
                    if _same_site(link, self.start_url_n, include_subdomains=self.include_subdomains) or self.follow_external:
                        if link not in self.visited_pages:
                            self.queue.append((link, depth + 1))
                            self._log(f"[enqueue] depth={depth+1} {link}")

            grouped.setdefault(page_url, set()).update(filtered)
            self.visited_pages.add(url)
            self.metrics.mark_success()
            if self.delay_seconds > 0:
                time.sleep(self.delay_seconds)

        grouped.setdefault(self.start_url_n, set())
        self.metrics.finalize(len(self.visited_pages))
        return {k: sorted(v) for k, v in grouped.items()}, self.metrics.as_dict()
