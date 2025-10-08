# WebCarto — Mapeador de URLs (Python)

WebCarto é um mapeador de URLs e páginas da web. Hoje ele:
- Faz download com `requests` e extrai links com `BeautifulSoup`.
- Pode navegar entre páginas internas (crawl) com limites de profundidade e páginas.
- Oferece saídas: lista simples, árvore por domínio (`--tree`) e por página (`--page-tree`).
 - Relatório opcional de risco por URL (`--risk-report`).

Visão (roadmap curto):
- Automatizar o relatório HTML (gerado hoje via `webcarto report`) para abrir resumo no navegador ao final do crawl.
- Expandir integrações de reputação (mais providers e scoring configurável).
- Adicionar testes automatizados e exemplos reproduzíveis para novos colaboradores.

Diagrama (alto nível)

```
[CLI webcarto]
   │
   ├─▶ crawler (BFS, robots, verbose)
   │      ├─ http_utils (requests, robots.txt)
   │      └─ html_utils (BeautifulSoup → <a href>)
   │
   ├─▶ transforms (ex.: domínio → host → URLs)
   ├─▶ metrics (runtime + agregado do resultado)
   └─▶ io_utils (JSON/CSV/TXT)
```

## Instalação

1. (Opcional) Crie e ative um virtualenv

   - macOS/Linux:
     ```bash
     python3 -m venv .venv && source .venv/bin/activate
     ```
   - Windows (PowerShell):
     ```powershell
     py -m venv .venv; .venv\Scripts\Activate.ps1
     ```

2. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```

3. (Opcional) Instale como CLI via entry point (desenvolvimento):
   ```bash
   pip install -e .
   # agora você pode chamar o binário diretamente
   webcarto --help
   webcarto --url https://example.com --out out/urls.json
   ```

### Outras formas de instalar o CLI

- Usuário local (sem virtualenv):
  ```bash
  pip install --user .
  # o binário ficará em ~/.local/bin/webcarto (Linux/macOS)
  # garanta que ~/.local/bin está no seu PATH
  webcarto --help
  ```

- Isolado (pipx, recomendado para utilitários):
  ```bash
  pipx install .
  webcarto --help
  # atualizar
  pipx upgrade webcarto
  # remover
  pipx uninstall webcarto
  ```

- Empacotado (wheel):
  ```bash
  python -m pip wheel . -w dist/
  pip install dist/webcarto-*.whl
  ```

Para desinstalar (pip):
```bash
pip uninstall webcarto
```

## Rodando (offline)

Extrai links do arquivo `data/sample_links.html` (sem internet):

```bash
webcarto --offline --out out/urls.json
```

Prévia de saída (offline):

```
01. https://example.org/
02. https://quotes.toscrape.com/
03. https://quotes.toscrape.com/about
04. https://quotes.toscrape.com/page/2
05. https://quotes.toscrape.com/page/3
06. https://quotes.toscrape.com/search?q=test
07. https://quotes.toscrape.com/tag/life
08. https://sub.quotes.toscrape.com/path

Collected 8 URLs from data/sample_links.html -> out/urls.json
```

## Rodando (online)

Coleta links a partir de uma URL inicial:

```bash
webcarto --url https://example.com --out out/urls.csv
```

Observações:
- Respeite os termos/`robots.txt` dos sites reais.
 - Retries/backoff: use `--retries` e `--retry-backoff` para tornar as requisições mais resilientes.
 - Logs persistentes: `--log out/crawl.log` grava o mesmo conteúdo do `--verbose` em arquivo.

## Relatório HTML unificado

Gera uma página única combinando `urls.json`, `risk.json` e `reputation.json` existentes no diretório `out/`:

```bash
# Usando o CLI já instalado (via pip install -e .)
webcarto report --out-dir out --output out/report.html

# Ou chamando o wrapper direto
python scripts/report_builder.py --out-dir out

# Abre o arquivo gerado
open out/report.html  # macOS (ou use xdg-open/Start-Process)
```

A subcomando `webcarto report` e o script aceitam `--output` para escolher outro caminho
e `--title` para personalizar o título mostrado.
- Quando `out/js-analysis.json` existir, o relatório inclui automaticamente uma
  seção com a análise dos scripts (categorias, flags e referências OWASP/MITRE).

## Análise de JavaScript pós-crawl

Use o novo subcomando para inspecionar scripts coletados (usa `out/urls.json` existente):

```bash
# assume que o crawl anterior já gerou out/urls.json
webcarto analyze-js --urls out/urls.json --output out/js-analysis.json

# opções úteis
webcarto analyze-js --script-url https://example.com/app.js   # ignora o JSON e analisa só esse script
webcarto analyze-js --limit 10                                # restringe a quantidade de scripts
webcarto analyze-js --quiet                                   # reduz logs (modo enxuto)
webcarto analyze-js --refresh                                 # refaz análise ignorando cache local
webcarto analyze-js --include-subdomains                      # trata subdomínios como internos
webcarto analyze-js --timeout 20 --retries 3 --retry-backoff 0.5
webcarto analyze-js --reputation out/reputation.json          # reutiliza resultados de reputação da última análise de risco
webcarto analyze-js --strict                                  # aborta na primeira falha
```

O arquivo `out/js-analysis.json` inclui hashes, heurísticas de ofuscação, amostras de
potenciais IOCs (`potential_ioc_sample`), categorias de comportamento suspeito por
token (`token_categories`), marcações de alto risco (`high_risk`) e, quando
disponível, a reputação do host reaproveitada de `out/reputation.json` (gerado por `--verify-reputation`).
Se `out/privacy.json` estiver presente, o relatório HTML exibirá também uma seção de
privacidade (cookies, trackers e issues encontrados durante a varredura).

Categorias de tokens atualmente suportadas (com referências OWASP/MITRE):
- `exec_dynamic`: uso de `eval`, `Function`, `setTimeout`/`setInterval` com strings (OWASP A03; MITRE T1059.007).
- `dom_injection`: manipulação direta do DOM (`document.write`, `innerHTML` suspeito) (OWASP A03/A05; MITRE T1185/T1608).
- `net_beacon`: chamadas de rede (`fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon`) (OWASP A05; MITRE T1071).
- `obfuscation`: sinais de ofuscação (`atob`, `crypto.subtle`, unicode invisível) (OWASP A04; MITRE T1027).
- `redirect_control`: escrita explícita em `window.location`/`location.href` (OWASP A01; MITRE T1204/T1185).
- `storage_sensitive`: leitura/escrita de `localStorage`, `sessionStorage`, `document.cookie` (OWASP A07; MITRE T1555).
- `third_party_loader`: `import()` dinâmico ou injeção de `<script>` (OWASP A08; MITRE T1105/T1608).
- `cross_context`: uso de `postMessage` sem validação aparente (OWASP A01/A08; MITRE T1102).

O campo `high_risk` fica `true` quando combinações como `exec_dynamic+obfuscation`,
`exec_dynamic+net_beacon`, `redirect_control+net_beacon` ou ofuscação extrema (score ≥7
com unicode e muitos possíveis IOCs) são detectadas.

## Auditoria de privacidade

```bash
# Usa as páginas do último crawl (out/urls.json) e grava em out/privacy.json
webcarto privacy-check --output out/privacy.json

# Com URL específica (sem precisar do JSON)
webcarto privacy-check --url https://example.com

# Personalizações úteis
webcarto privacy-check --limit 5            # audita apenas as N primeiras páginas do JSON
webcarto privacy-check --timeout 30000      # aumenta o timeout do Playwright (ms)
webcarto privacy-check --no-headless        # abre o navegador visível (depuração)
webcarto privacy-check --reputation out/reputation.json
webcarto privacy-check --quiet              # reduz logs no terminal
```

O arquivo `out/privacy.json` lista cookies (incluindo terceiros), trackers conhecidos,
possíveis sinais de fingerprinting, formulários que enviam dados para domínios
externos e demais issues semelhantes ao Blacklight.

> Após instalar as dependências (`pip install -r requirements.txt`), execute
> `playwright install chromium` uma única vez para baixar o navegador headless.

## Estrutura

- `src/webcarto/cli.py`: script CLI e orquestração (parse de flags, chamada do crawler, transforms e IO).
- `src/webcarto/crawler.py`: classe `Crawler` (BFS, verbose, respeito a robots) e `CrawlParams`.
- `src/webcarto/html_utils.py`: parsing de HTML e extração de `<a href>` (ordem estável, normalização).
- `src/webcarto/http_utils.py`: download HTTP (`requests`), detecção de HTML e carga de `robots.txt`.
- `src/webcarto/urls_utils.py`: utilitários de URL (normalização, mesmo site, PSL/domínio base, agrupamento por host).
- `src/webcarto/transforms.py`: agregações/relatórios (ex.: `build_domain_tree`), filtros opcionais e resumos por página.
- `src/webcarto/metrics.py`: métricas de runtime (`CrawlMetrics`) e agregadas de resultado (`compute_result_metrics`).
- `src/webcarto/io_utils.py`: serialização (JSON/CSV/TXT) e leitura de arquivos locais.
- `src/webcarto/reputation.py` e `src/webcarto/risk.py`: reputação externa e heurísticas de risco.
- `webcarto report` / `scripts/report_builder.py`: utilitário para gerar relatório HTML a partir de `out/*.json`.
- `data/sample_links.html`: HTML estático para testes offline.
- `out/`: pasta ignorada pelo Git para artefatos e relatórios.
- `requirements.txt`: dependências do Python.

## Exemplos

```bash
# Online: varre o domínio (mesmo host), até 200 páginas e profundidade 2
webcarto --url https://example.com --out out/urls.json

# CSV com uma coluna "url"
webcarto --url https://example.com --out out/urls.csv

# Texto simples, um por linha
webcarto --url https://example.com --out out/urls.txt

# Restrições e performance
webcarto --url https://example.com \
  --max-pages 500 --max-depth 3 --delay 0.2

# Expandir para outros domínios (segue links externos)
webcarto --url https://example.com --all-domains

# Offline/local: extrai links de um arquivo HTML, resolvendo relativos via --base-url
webcarto --offline --input-file data/sample_links.html --base-url https://quotes.toscrape.com/

# Restringir navegação a host exato (sem subdomínios)
webcarto --url https://example.com --no-subdomains --out out/urls.json

# Retries/backoff e logs persistentes
webcarto --url https://example.com --retries 3 --retry-backoff 0.5 --verbose --log out/crawl.log

# Relatório de risco (gera JSON separado)
webcarto --url https://example.com --risk-report out/urls_risk.json
webcarto --url https://example.com --page-tree --risk-report out/urls_risk.json
webcarto --offline --input-file data/sample_links.html --risk-report out/urls_risk.json
webcarto --url https://example.com --risk-report out/urls_risk.json --verify-redirects
```

### Saída em árvore por domínio

Para agrupar os links por domínio/subdomínio, use `--tree`.

Exemplos:

```bash
# Online (JSON): { "domain": { "host": ["url", ...] }, ... }
webcarto --url https://example.com --tree --out out/urls_tree.json

# CSV: colunas "domain","host","url"
webcarto --url https://example.com --tree --out out/urls_tree.csv

# TXT: linhas "domain<TAB>host<TAB>url"
webcarto --url https://example.com --tree --out out/urls_tree.txt

# Offline com árvore
webcarto --offline --input-file data/sample_links.html \
  --base-url https://quotes.toscrape.com/ --tree --out out/urls_tree.json
```

Esquema JSON (padronizado)
- O JSON é sempre envolvido por um envelope com chaves claras, incluindo o tipo de saída e metadados.

```json
{
  "schema": "site-scraper.urls#1",
  "kind": "list" | "page_tree" | "domain_tree",
  "generated_at": "2025-08-31T00:00:00Z",
  "meta": { "source": "...", "params": { /* quando aplicável */ } },
  "items": [
    { "url": "https://..." },
    { "page": "https://...", "url": "https://..." },
    { "domain": "exemplo.com.br", "host": "www.exemplo.com.br", "url": "https://..." }
  ]
}
```

### Saída por página (page -> URLs)

Para ver os links agrupados pela página onde foram encontrados (como o antigo `--grouped`), use `--page-tree`.

```bash
# Online (JSON): { "pagina": ["url1", "url2", ...], ... }
webcarto --url https://example.com --page-tree --out out/urls_by_page.json

# CSV: colunas "page","url"
webcarto --url https://example.com --page-tree --out out/urls_by_page.csv

# TXT: linhas "page<TAB>url"
webcarto --url https://example.com --page-tree --out out/urls_by_page.txt

# Offline por página (um grupo)
webcarto --offline --input-file data/sample_links.html \
  --base-url https://quotes.toscrape.com/ --page-tree --out out/urls_by_page.json
```

## Relatório de risco (URLs)

Gere um relatório separado com heurísticas de risco de URL usando `--risk-report out/urls_risk.json`. Esse relatório não altera o arquivo principal (`--out`).

Heurísticas (exemplos de tags):
- ip-literal, credentials-in-url, nonstd-port, punycode-idn, risky-tld
- shortener, webhook-endpoint, paste-site
- executable, archive, macro-doc (por extensão)
- document-pdf, document-office (documentos; baixo risco por padrão)
- param-redirect (URLs dentro de parâmetros), base64-url (param base64 vira URL)
- pii/secret-in-url (chaves: email/token/key/password/secret)
- mixed-content (em `--page-tree`/offline com base-url)

Exceções e ajustes de contexto:
- Para links do WhatsApp (`api.whatsapp.com`, `wa.me`, `web.whatsapp.com`) com `phone=...`, não marcamos PII; em vez disso emitimos a tag `contact-phone` (intencional, score 0).

Campos adicionais quando há redirecionamento em parâmetro:
- `target_url`: alvo decodificado do parâmetro (quando detectável)
- `external_target`: se o alvo é externo ao domínio da URL
- `encoding`: plain | percent | base64
- Com `--verify-redirects`, URLs com `param-redirect` são testadas via HEAD e recebem:
  - tag extra `server-redirect-detected` quando há 3xx para domínio externo
  - `redirect_status` (código 3xx) e `redirect_location`

Formato do relatório (JSON):
```json
{
  "schema": "site-scraper.risk#1",
  "kind": "risk_list",
  "generated_at": "2025-08-31T00:00:00Z",
  "meta": { "source": "...", "params": { "mode": "list|tree|page-tree" } },
  "metrics": { "total": 0, "by_tag": { }, "risk_buckets": {"high":0,"medium":0,"low":0} },
  "items": [
    { "url": "https://...", "page": "https://...", "tags": ["..."], "reasons": ["..."], "score": 0 }
  ]
}
```

Campos adicionais por item (quando disponíveis)
- `link_type`: "page" | "asset:image" | "asset:style" | "asset:script"
- `ownership`: "internal" | "external" (comparado com a origem)
- `reputation`: mapa `{ "provider": { "verdict": "clean|suspicious|malicious|unknown", "score": 0, "categories": [], "source": "host|url" } }`
- Tags derivadas de reputação: `reputation:malicious | reputation:suspicious | reputation:clean | reputation:unknown`

Métricas adicionais (quando reputação ativa)
- `reputation_summary`: contagens por veredicto consolidado
- `by_provider_verdict`: contagens por provider x veredicto
- `top_flagged_hosts`: top hosts marcados como `malicious|suspicious`

Exemplo com reputação (trecho)
```json
{
  "schema": "site-scraper.risk#1",
  "kind": "risk_list",
  "metrics": {
    "total": 2,
    "by_tag": { "reputation:suspicious": 1, "reputation:clean": 1 },
    "risk_buckets": { "high": 0, "medium": 1, "low": 1 },
    "reputation_summary": { "malicious": 0, "suspicious": 1, "clean": 1, "unknown": 0 },
    "by_provider_verdict": { "vt": { "clean": 2 }, "otx": { "suspicious": 1, "clean": 1 } },
    "top_flagged_hosts": [["cdn.example.com", 1]]
  },
  "items": [
    {
      "url": "https://cdn.example.com/js/app.js",
      "tags": ["third-party-js", "reputation:suspicious"],
      "reasons": ["Script de terceiro referenciado"],
      "score": 3,
      "link_type": "asset:script",
      "ownership": "external",
      "reputation": {
        "vt": { "verdict": "clean", "score": 0, "categories": [], "source": "host" },
        "otx": { "verdict": "suspicious", "score": 3, "categories": ["otx:pulse"], "source": "host" }
      }
    },
    {
      "url": "https://example.org/",
      "tags": ["reputation:clean"],
      "reasons": [],
      "score": 0,
      "link_type": "page",
      "ownership": "external",
      "reputation": {
        "vt": { "verdict": "clean", "score": 0, "categories": [], "source": "host" },
        "otx": { "verdict": "clean", "score": 0, "categories": [], "source": "host" }
      }
    }
  ]
}
```


Notas:
- Por padrão respeita `robots.txt`. Desative com `--no-robots` (use com responsabilidade).
- Coleta padrão: apenas links de `<a href="...">`; esquemas não-HTTP(S) são ignorados (mailto, tel, javascript).
- Com `--include-assets`/`--include-forms`, assets/forms entram na SAÍDA, mas apenas links `<a>` são enfileirados para navegação.
- `--only-internal` também filtra a saída para assets/forms, removendo externos do resultado.
- Subdomínios (incluindo `www.`) são tratados como parte do mesmo site para navegação interna; desative com `--no-subdomains` para exigir host exato.
- O campo "domain" usa a Public Suffix List (PSL) para calcular o domínio base (eTLD+1). Se a PSL não estiver disponível, usa fallback simples.
 - PSL e cache: o script mantém um cache local em `.tldcache/` e tenta atualizar a PSL automaticamente uma vez por dia. Se não houver rede, usa o cache existente; se não houver cache, usa o snapshot embutido do tldextract.

### Ordem de visita (determinística)
- Prioridade ao enfileirar páginas para navegação (BFS):
  1) mesmo host do alvo (com `www.` normalizado), 2) subdomínios do alvo (se `--no-subdomains` não estiver ativo), 3) externos.
- Dentro de cada grupo, a ordem segue o DOM (ordem de aparição no HTML), deduplicando de forma estável.
- `--max-depth` e `--max-pages` continuam valendo normalmente; `--all-domains` permite seguir externos; `--only-internal` filtra apenas a SAÍDA.

### Flags principais
- `--max-pages`: máximo de páginas a visitar (BFS). Ex.: 100
- `--max-depth`: profundidade (0 = só a página inicial). Ex.: 1
- `--all-domains`: também segue links externos (outros domínios)
- `--only-internal`: filtra a saída para mostrar apenas URLs internas
- `--no-subdomains`: considera apenas o host exato como interno
- `--tree`: agrupa saída por domínio/subdomínio (domain -> host -> [urls])
- `--page-tree`: agrupa por página onde os links foram encontrados (page -> [urls])
- `--include-assets`: também coleta assets (`img/src`, `script/src`, `link/href`)
- `--include-forms`: também coleta ações de formulários (`form/action`)
 - `--retries`: tentativas por requisição HTTP (com backoff exponencial)
 - `--retry-backoff`: fator do backoff (ex.: 0.3 → 0.3s, 0.6s, 1.2s...)
 - `--log`: caminho de arquivo para persistir logs do `--verbose`
- `--risk-report`: gera relatório de risco separado (JSON)
- `--verify-redirects`: verifica via HEAD se parâmetros geram 3xx externo
- `--verify-reputation`: consulta reputação externa (providers) — infra
- `--reputation-providers`: lista de providers (ex.: vt,gsb,urlhaus,otx)
- `--reputation-cache`: caminho do cache de reputação (JSON, padrão `out/reputation-cache.json`)
- `--reputation-output`: arquivo com os resultados da reputação para o site atual (padrão `out/reputation.json`)
- `--reputation-ttl`: TTL do cache (ex.: 7d, 24h, 3600s)
- `--reputation-concurrency`: paralelismo das consultas
- `--reputation-timeout`: timeout por requisição (s)
- `--reputation-include-query`: inclui querystring nas consultas (com scrubbing)
- `--reputation-scrub-params`: chaves de query a remover (csv)
- `--reputation-keys`: chaves dos providers (ex.: vt=KEY,gsb=KEY,otx=KEY)
- `--reputation-strict`: erro se provider listado não tiver chave configurada
- `--reputation-dry-run`: usa apenas cache/stub (sem rede)
- `--reputation-self-test`: executa autoteste dos providers configurados (retorna JSON no stdout)

Chaves via variáveis de ambiente (opcional)
- Defina as chaves como variáveis de ambiente para auto‑detecção dos providers (sem passar `--reputation-providers`):
  - `VT_API_KEY` (VirusTotal)
  - `GSB_API_KEY` (Google Safe Browsing)
- `OTX_API_KEY` (AlienVault OTX)
- `URLHAUS_AUTH_KEY` (URLhaus bulk API)
- Alternativa: use `--reputation-keys vt=...,gsb=...,otx=...,urlhaus=...` diretamente no CLI.

Privacidade (scrubbing) em reputação
- Por padrão consultamos por host (sem querystring). Para incluir a query, use `--reputation-include-query`.
- Mesmo incluindo a query, removemos chaves comuns de tracking (ex.: `utm_*`, `gclid`, `fbclid`, `trk`, `ref`, `src`). Ajuste com `--reputation-scrub-params`.

### Verbose + métricas de erros
- `--verbose`: loga eventos do crawler (erros HTTP/exceções, bloqueios por robots, respostas não‑HTML).
- O envelope JSON em `metrics` inclui campos adicionais quando o crawler é usado online:
  - `success_pages_count`: páginas HTML processadas com sucesso
  - `visited_pages_count`: total de páginas consideradas (inclui erros/não‑HTML)
  - `robots_blocked_count`: páginas bloqueadas por `robots.txt`
  - `non_html_pages_count`: respostas cujo `Content-Type` não contém HTML
  - `http_status_histogram`: mapa `status_code -> contagem`
  - `exception_histogram`: mapa `ExceptionType -> contagem`
  - `request_count`: quantidade de requisições HTTP realizadas
  - `total_request_time_ms` e `avg_request_time_ms`: soma e média (ms) dos tempos por requisição

Em modo `--verbose`, cada página visitada imprime uma linha com resultado e tempo:

```
[visit] depth=0 https://exemplo.com/
[enqueue] depth=1 https://exemplo.com/about
[enqueue] depth=1 https://exemplo.com/products
[ok] 200 123ms https://exemplo.com/ (42 links)
[skip] non-HTML 200 8ms https://exemplo.com/logo.png (image/png)
[robots] blocked: https://exemplo.com/admin
[error] 500 97ms https://exemplo.com/api -> HTTPError
```

Com `--log`, os mesmos logs verbosos também são gravados no arquivo indicado (append).

## Arquitetura (visão geral)

- Entrada/Coleta: `src/webcarto/crawler.py` usa `http_utils` (requisições/robots) e `html_utils` (parsing) para navegar via BFS com limites (`--max-pages`, `--max-depth`).
- Organização de dados: `src/webcarto/urls_utils.py` centraliza normalização/comparação e PSL; `src/webcarto/transforms.py` agrega (p.ex. domínio → host → URLs).
- Métricas: `src/webcarto/metrics.py` coleta tempos/erros (runtime) e sumariza o resultado (hosts/domínios, internos/externos).
- Saída: `src/webcarto/io_utils.py` escreve JSON/CSV/TXT em um envelope padronizado.
- CLI: `src/webcarto/cli.py` orquestra os componentes conforme as flags; no modo online `--page-tree` roda um único crawl (sem duplicação de visitas).
- `--env-file`: carrega variáveis do arquivo `.env` (se omitido, tenta `./.env` se existir)
- `--config`: arquivo INI com defaults (ex.: `webcarto.ini`), seção `[reputation]`
- Arquivo `.env` (opcional):
  - Crie um arquivo `.env` na raiz do projeto com linhas `CHAVE=valor`, por exemplo:
    - `VT_API_KEY=...`
    - `GSB_API_KEY=...`
    - `OTX_API_KEY=...`
  - O CLI carrega automaticamente `./.env` (ou um arquivo passado com `--env-file`).

Arquivo de configuração INI (opcional)
- Use `--config webcarto.ini` (ou crie `webcarto.ini` na raiz). Seção suportada nesta fase:
  - `[reputation]`
    - `providers = vt,gsb,urlhaus,otx`
    - `cache = out/reputation-cache.json`
    - `output = out/reputation.json`
    - `ttl = 7d`
    - `concurrency = 2`
    - `timeout = 10`
    - `include_query = false`
    - `scrub_params = utm_*,gclid,fbclid,trk,ref,src`
    - `keys = vt=AAA,gsb=BBB,otx=CCC,urlhaus=DDD`
  - Precedência: CLI > INI > ENV/defaults. Para `providers` e `keys`, se não passados no CLI, o INI é usado; caso contrário, aplica-se o comportamento descrito nas flags.

Autoteste de reputação
- Verifica rapidamente se os providers estão configurados e com chaves válidas, tentando endpoints leves:
  - URLhaus (sem chave): POST host example.com → 200/ok/no_results
  - VT: GET domains/example.com com `x-apikey` → 200
  - GSB: POST threatMatches com URL example.com → 200
  - OTX: GET pulses/subscribed com `X-OTX-API-KEY` → 200/204
- Uso:
  - `webcarto --reputation-self-test --reputation-dry-run` (simula, marca todos como skipped)
  - `webcarto --reputation-self-test` (real; requer rede e chaves quando aplicável)
- Saída (exemplo):
  ```json
  {
    "reputation_self_test": {
      "urlhaus": {"status":"ok","http_status":200},
      "vt": {"status":"ok","http_status":200},
      "gsb": {"status":"fail","http_status":401},
      "otx": {"status":"no_key"}
    }
  }
  ```
