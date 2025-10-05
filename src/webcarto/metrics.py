from typing import Any, Dict, List, Optional

from .urls_utils import _domain_of_url, _hostname_of_url, _same_site


class CrawlMetrics:
    """Coleta e expõe métricas do crawler (runtime)."""

    def __init__(self) -> None:
        self.data: Dict[str, Any] = {
            "success_pages_count": 0,
            "robots_blocked_count": 0,
            "non_html_pages_count": 0,
            "http_status_histogram": {},
            "exception_histogram": {},
            "request_count": 0,
            "total_request_time_ms": 0.0,
        }

    def inc_robot_block(self) -> None:
        self.data["robots_blocked_count"] = self.data.get("robots_blocked_count", 0) + 1

    def record_request(self, status_code: Optional[int], elapsed_ms: float) -> None:
        self.data["request_count"] += 1
        self.data["total_request_time_ms"] += float(elapsed_ms)
        if status_code is not None:
            hist = self.data["http_status_histogram"]
            hist[str(status_code)] = hist.get(str(status_code), 0) + 1

    def record_exception(self, exc: BaseException) -> None:
        et = type(exc).__name__
        hist = self.data["exception_histogram"]
        hist[et] = hist.get(et, 0) + 1

    def mark_non_html(self) -> None:
        self.data["non_html_pages_count"] = self.data.get("non_html_pages_count", 0) + 1

    def mark_success(self) -> None:
        self.data["success_pages_count"] = self.data.get("success_pages_count", 0) + 1

    def finalize(self, visited_count: int) -> None:
        self.data["visited_pages_count"] = int(visited_count)
        if self.data.get("request_count"):
            self.data["avg_request_time_ms"] = round(
                self.data["total_request_time_ms"] / max(1, self.data["request_count"]), 2
            )

    def as_dict(self) -> Dict[str, Any]:
        return dict(self.data)


def compute_result_metrics(
    urls: List[str],
    origin: Optional[str],
    include_subdomains: bool,
    pages_count: Optional[int] = None,
) -> Dict[str, Any]:
    """Métricas agregadas do resultado (por URL/host/domínio)."""
    total = len(urls)
    unique_urls = len(set(urls))
    hosts = [_hostname_of_url(u) for u in urls]
    hosts = [h for h in hosts if h]
    domains = [_domain_of_url(u) for u in urls]
    domains = [d for d in domains if d]
    by_host: Dict[str, int] = {}
    for h in hosts:
        by_host[h] = by_host.get(h, 0) + 1
    by_domain: Dict[str, int] = {}
    for d in domains:
        by_domain[d] = by_domain.get(d, 0) + 1
    internal = external = None
    if origin:
        internal = 0
        external = 0
        for u in urls:
            if _same_site(u, origin, include_subdomains=include_subdomains):
                internal += 1
            else:
                external += 1
    metrics: Dict[str, Any] = {
        "total_items": total,
        "unique_urls": unique_urls,
        "unique_hosts": len(set(hosts)),
        "unique_domains": len(set(domains)),
        "by_host": by_host,
        "by_domain": by_domain,
    }
    if internal is not None:
        metrics.update({
            "internal_count": internal,
            "external_count": external,
        })
    if pages_count is not None:
        metrics["pages_count"] = pages_count
    return metrics
