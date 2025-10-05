import argparse
import datetime as _dt
import html
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


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
        if isinstance(value, dict):
            inner = "".join(
                f"<span class=\"metric-chip\"><strong>{_escape(sub_key)}</strong>: {_escape(sub_val)}</span>"
                for sub_key, sub_val in value.items()
            )
            parts.append(
                f"<div class=\"metric-block\"><div class=\"metric-title\">{_escape(key)}</div>{inner}</div>"
            )
        else:
            parts.append(
                f"<div class=\"metric-block\"><div class=\"metric-title\">{_escape(key)}</div><span>{_escape(value)}</span></div>"
            )
    return "".join(parts)


def _render_tags(tags: Iterable[str]) -> str:
    return "".join(f"<span class=\"tag\">{_escape(tag)}</span>" for tag in tags)


def render_report(
    title: str,
    urls: Optional[Dict[str, Any]],
    risk: Optional[Dict[str, Any]],
    reputation: Optional[Dict[str, Any]],
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

    reputation_items: List[Dict[str, Any]] = []
    if reputation:
        for host, data in sorted((reputation.get("items") or {}).items()):
            providers = data.get("providers") or {}
            reputation_items.append({
                "host": host,
                "providers": providers,
                "last": data.get("last"),
            })

    url_rows = "".join(
        f"<tr><td>{_escape(item.get('page'))}</td><td>{_escape(item.get('url'))}</td></tr>"
        for item in url_items
    ) or "<tr><td colspan=\"2\" class=\"empty\">Nenhuma URL encontrada.</td></tr>"

    risk_rows = "".join(
        "<tr>"
        f"<td>{_escape(entry.get('url'))}</td>"
        f"<td>{_escape(entry.get('page'))}</td>"
        f"<td>{_render_tags(entry.get('tags') or [])}</td>"
        f"<td>{_escape(', '.join(entry.get('reasons') or []))}</td>"
        f"<td>{_escape(entry.get('score'))}</td>"
        "</tr>"
        for entry in risk_items
    ) or "<tr><td colspan=\"5\" class=\"empty\">Nenhum risco apontado.</td></tr>"

    reputation_rows = []
    for item in reputation_items:
        provider_badges = []
        for provider, pdata in sorted(item["providers"].items()):
            payload = pdata.get("data") if isinstance(pdata, dict) else None
            verdict = (payload or pdata).get("verdict") if isinstance(payload or pdata, dict) else ""
            score = (payload or pdata).get("score") if isinstance(payload or pdata, dict) else ""
            categories = ", ".join((payload or pdata).get("categories", [])) if isinstance(payload or pdata, dict) else ""
            provider_badges.append(
                "<div class=\"provider-chip\">"
                f"<span class=\"provider\">{_escape(provider)}</span>"
                f"<span class=\"verdict\">{_escape(verdict)}</span>"
                f"<span class=\"score\">{_escape(score)}</span>"
                f"<span class=\"categories\">{_escape(categories)}</span>"
                "</div>"
            )
        provider_html = "".join(provider_badges) or "<span class=\"empty\">Sem dados</span>"
        reputation_rows.append(
            "<tr>"
            f"<td>{_escape(item['host'])}</td>"
            f"<td>{provider_html}</td>"
            "</tr>"
        )
    reputation_table_body = "".join(reputation_rows) or "<tr><td colspan=\"2\" class=\"empty\">Sem dados de reputacao.</td></tr>"

    metrics_html = _build_metric_list(risk_metrics)

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
    }}
    .metric-title {{
      font-weight: 600;
      font-size: 0.95rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
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
    .table-container {{
      width: 100%;
      overflow-x: auto;
      border-radius: 12px;
    }}
    .table-container table {{
      width: 100%;
      min-width: 640px;
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
      align-items: center;
      gap: 8px;
      padding: 6px 12px;
      border-radius: 999px;
      background: rgba(15,23,42,0.07);
      margin: 4px 8px 4px 0;
      font-size: 0.82rem;
    }}
    .provider {{ font-weight: 700; }}
    .verdict {{ text-transform: uppercase; letter-spacing: 0.04em; }}
    .score {{ color: var(--accent); font-weight: 600; }}
    .categories {{ color: var(--muted); font-size: 0.75rem; }}
    .empty {{ color: var(--muted); text-align: center; padding: 32px 0; }}
    .filters {{ display: flex; gap: 12px; flex-wrap: wrap; margin-top: 12px; }}
    .filters input {{
      padding: 10px 14px;
      border-radius: 10px;
      border: 1px solid rgba(148,163,184,0.6);
      min-width: 200px;
      font-size: 0.95rem;
      background: rgba(255,255,255,0.9);
    }}
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
    document.addEventListener('DOMContentLoaded', function() {{
      setupFilter('urls-filter', 'urls-table');
      setupFilter('risk-filter', 'risk-table');
      setupFilter('reputation-filter', 'reputation-table');
    }});
  </script>
</head>
<body>
  <header>
    <h1>{_escape(title)}</h1>
    <div class=\"meta\">
      <div><strong>Fonte:</strong> {_escape(source) or 'n/d'}</div>
      <div><strong>Gerado em:</strong> {_escape(generated_display) or 'n/d'}</div>
      <div><strong>Compilado em:</strong> {_escape(now_str)}</div>
    </div>
  </header>
  <main>
    <section>
      <h2>Resumo de metricas</h2>
      <p class=\"muted\">Valores agregados do relatorio de risco. Metricas adicionais aparecem como chips agrupados.</p>
      <div class=\"metric-grid\">{metrics_html or '<div class=\"empty\">Sem metricas carregadas.</div>'}</div>
    </section>

    <section>
      <h2>URLs coletadas ({len(url_items)})</h2>
      <div class=\"filters\">
        <input id=\"urls-filter\" type=\"search\" placeholder=\"Filtrar por URL ou pagina...\" aria-label=\"Filtro de URLs\" />
      </div>
      <div class=\"table-container\">
        <table id=\"urls-table\">
          <thead>
            <tr><th>Pagina</th><th>URL</th></tr>
          </thead>
          <tbody>
            {url_rows}
          </tbody>
        </table>
      </div>
    </section>

    <section>
      <h2>Itens de risco ({len(risk_items)})</h2>
      <div class=\"filters\">
        <input id=\"risk-filter\" type=\"search\" placeholder=\"Filtrar por risco...\" aria-label=\"Filtro de riscos\" />
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

    <section>
      <h2>Reputacao por host ({len(reputation_items)})</h2>
      <div class=\"filters\">
        <input id=\"reputation-filter\" type=\"search\" placeholder=\"Filtrar por host ou provedor...\" aria-label=\"Filtro de reputacao\" />
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

    if not any([urls, risk, reputation]):
        raise SystemExit("Nenhum arquivo de saida encontrado para compor o relatorio.")

    html_doc = render_report(args.title, urls, risk, reputation)

    output_path = Path(args.output) if args.output else out_dir / "report.html"
    output_path.write_text(html_doc, encoding="utf-8")
    print(f"Relatorio salvo em {output_path}")
    return 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
