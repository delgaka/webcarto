from pathlib import Path
from typing import List, Dict, Optional, Any, Union
import json
import datetime


def read_file(path: Path) -> str:
    """Lê um arquivo texto em UTF-8 e retorna seu conteúdo."""
    return path.read_text(encoding="utf-8")


def save_output(
    data: Union[List[str], Dict[str, List[str]], Dict[str, Dict[str, List[str]]]],
    out_path: Path,
    fmt: str = "json",
    *,
    meta: Optional[Dict[str, Any]] = None,
    metrics: Optional[Dict[str, Any]] = None,
) -> None:
    """Salva os dados em `out_path` nos formatos json/csv/txt.

    - Suporta: lista simples de URLs, agrupamento por página (dict[page -> [urls]])
      e árvore por domínio (dict[domain -> dict[host -> [urls]]]).
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # Aceita: list[str], dict[str, list[str]] ou dict[str, dict[str, list[str]]]
    if fmt == "json":
        # Normaliza saída JSON para um envelope com chaves bem definidas
        kind = None
        items: List[Dict[str, Any]] = []
        if isinstance(data, list):
            kind = "list"
            items = [{"url": u} for u in data]
        elif isinstance(data, dict):
            values = list(data.values())
            is_tree = bool(values) and isinstance(values[0], dict)
            if is_tree:
                kind = "domain_tree"
                for domain in sorted(data.keys()):  # type: ignore[arg-type]
                    hosts: Dict[str, List[str]] = data[domain]  # type: ignore[assignment]
                    for host in sorted(hosts.keys()):
                        for url in hosts[host]:
                            items.append({"domain": domain, "host": host, "url": url})
            else:
                kind = "page_tree"
                for page in sorted(data.keys()):  # type: ignore[arg-type]
                    for url in data[page]:  # type: ignore[index]
                        items.append({"page": page, "url": url})
        payload = {
            "schema": "site-scraper.urls#1",
            "kind": kind,
            # timezone-aware UTC timestamp (Py3.9+ compatible), keep 'Z' suffix
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "meta": meta or {},
            "metrics": metrics or {},
            "items": items,
        }
        out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return

    # CSV/TXT
    import csv
    if isinstance(data, dict):
        # Detecta dict aninhado (árvore: domain -> host -> [urls]) vs dict plano (chave -> [urls])
        values = list(data.values())
        is_tree = bool(values) and isinstance(values[0], dict)
        if fmt == "csv":
            with out_path.open("w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                if is_tree:
                    writer.writerow(["domain", "host", "url"])  # cabeçalho
                    for domain in sorted(data.keys()):
                        hosts: Dict[str, List[str]] = data[domain]  # type: ignore[assignment]
                        for host in sorted(hosts.keys()):
                            for url in sorted(hosts[host]):
                                writer.writerow([domain, host, url])
                else:
                    writer.writerow(["page", "url"])  # cabeçalho
                    for key in sorted(data.keys()):
                        for url in sorted(data[key]):
                            writer.writerow([key, url])
        elif fmt == "txt":
            lines: List[str] = []
            if is_tree:
                for domain in sorted(data.keys()):
                    hosts: Dict[str, List[str]] = data[domain]  # type: ignore[assignment]
                    for host in sorted(hosts.keys()):
                        for url in sorted(hosts[host]):
                            lines.append(f"{domain}\t{host}\t{url}")
            else:
                for key in sorted(data.keys()):
                    for url in sorted(data[key]):
                        lines.append(f"{key}\t{url}")
            out_path.write_text("\n".join(lines), encoding="utf-8")
        else:
            raise ValueError("Unsupported format: %s" % fmt)
        return

    # data é list
    if fmt == "csv":
        with out_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["url"])  # cabeçalho
            for url in data:  # type: ignore
                writer.writerow([url])
    elif fmt == "txt":
        out_path.write_text("\n".join([str(x) for x in data]), encoding="utf-8")
    else:
        raise ValueError("Unsupported format: %s" % fmt)


def save_risk_report(
    items: List[Dict[str, Any]],
    out_path: Path,
    *,
    meta: Optional[Dict[str, Any]] = None,
    metrics: Optional[Dict[str, Any]] = None,
) -> None:
    """Salva relatório de risco em envelope JSON padronizado.

    items: lista de dicts com ao menos {url, tags, reasons, score} e opcional {page}.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": "site-scraper.risk#1",
        "kind": "risk_list",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "meta": meta or {},
        "metrics": metrics or {},
        "items": items,
    }
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
