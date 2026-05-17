"""Production support: org auth registry, background jobs, and dashboard HTML."""

from __future__ import annotations

import threading
from typing import Dict

from .models import BackgroundImportRequest, OrgConfigInput, SourceImportRequest
from .source_control import HistoryImporter
from .storage import Store


class OrgRegistry:
    def __init__(self, store: Store):
        self.store = store

    def upsert(self, item: OrgConfigInput) -> Dict[str, object]:
        return self.store.upsert_org_config(item.model_dump())

    def list(self) -> Dict[str, object]:
        return {"orgs": self.store.list_org_configs()}


class BackgroundJobManager:
    def __init__(self, store: Store, importer: HistoryImporter):
        self.store = store
        self.importer = importer
        self._threads: Dict[str, threading.Thread] = {}

    def start_import(self, item: BackgroundImportRequest) -> Dict[str, object]:
        payload = item.model_dump()
        existing = self.store.get_background_job(item.job_id)
        if existing and existing["status"] == "running":
            return existing
        self.store.upsert_background_job(item.job_id, "import-history", "queued", payload)

        def run() -> None:
            self.store.upsert_background_job(item.job_id, "import-history", "running", payload)
            try:
                result = self.importer.import_from_request(
                    SourceImportRequest(
                        provider=item.provider,
                        repo=item.repo,
                        token_env=item.token_env,
                        base_url=item.base_url,
                        limit=item.limit,
                        include_closed=item.include_closed,
                        import_decisions=item.import_decisions,
                        analyze=item.analyze,
                    )
                ).model_dump()
                self.store.upsert_background_job(item.job_id, "import-history", "completed", payload, result=result)
            except Exception as exc:  # pragma: no cover - background defensive boundary
                self.store.upsert_background_job(item.job_id, "import-history", "failed", payload, error=str(exc))

        thread = threading.Thread(target=run, daemon=True)
        self._threads[item.job_id] = thread
        thread.start()
        return self.store.get_background_job(item.job_id) or {}

    def status(self, job_id: str | None = None) -> Dict[str, object]:
        if job_id:
            return {"job": self.store.get_background_job(job_id)}
        return {
            "jobs": self.store.list_background_jobs(),
            "running": [name for name, thread in self._threads.items() if thread.is_alive()],
        }


def dashboard_html() -> str:
    return """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SentinelGraph</title>
  <style>
    :root { color-scheme: light; --ink: #18212f; --muted: #657083; --line: #d9dee8; --bg: #f7f8fb; --accent: #0f766e; --risk: #b42318; }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: var(--bg); color: var(--ink); }
    header { padding: 18px 28px; border-bottom: 1px solid var(--line); background: #fff; display: flex; align-items: center; justify-content: space-between; gap: 16px; }
    h1 { font-size: 20px; margin: 0; letter-spacing: 0; }
    main { max-width: 1180px; margin: 0 auto; padding: 24px; display: grid; gap: 20px; }
    section { background: #fff; border: 1px solid var(--line); border-radius: 8px; padding: 16px; }
    h2 { font-size: 15px; margin: 0 0 12px; }
    .grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
    .metric { border-left: 4px solid var(--accent); padding: 8px 10px; background: #f9fbfb; min-height: 64px; }
    .metric b { display: block; font-size: 24px; line-height: 1.1; }
    .metric span { color: var(--muted); font-size: 12px; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { text-align: left; padding: 9px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
    th { color: var(--muted); font-weight: 600; }
    .critical, .high { color: var(--risk); font-weight: 700; }
    .toolbar { display: flex; gap: 8px; align-items: center; }
    input { height: 34px; border: 1px solid var(--line); border-radius: 6px; padding: 0 10px; min-width: 240px; }
    button { height: 34px; border: 1px solid #0f766e; background: #0f766e; color: white; border-radius: 6px; padding: 0 12px; cursor: pointer; }
    @media (max-width: 800px) { header { align-items: stretch; flex-direction: column; } .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } input { min-width: 0; width: 100%; } }
  </style>
</head>
<body>
  <header>
    <h1>SentinelGraph</h1>
    <div class="toolbar">
      <input id="repo" value="payments-platform" aria-label="Repository">
      <button onclick="load()">Refresh</button>
    </div>
  </header>
  <main>
    <section>
      <h2>Operational Summary</h2>
      <div class="grid" id="metrics"></div>
    </section>
    <section>
      <h2>High Risk Findings</h2>
      <table><thead><tr><th>Severity</th><th>Title</th><th>File</th><th>Status</th></tr></thead><tbody id="findings"></tbody></table>
    </section>
    <section>
      <h2>Recent Risk Analyses</h2>
      <table><thead><tr><th>Subject</th><th>Level</th><th>Score</th><th>Summary</th></tr></thead><tbody id="analyses"></tbody></table>
    </section>
  </main>
  <script>
    async function load() {
      const repo = document.getElementById('repo').value.trim();
      const data = await fetch('/dashboard?repo=' + encodeURIComponent(repo)).then(r => r.json());
      const counts = data.counts || {};
      document.getElementById('metrics').innerHTML = ['entities','findings','analyses','incidents'].map(k => `<div class="metric"><b>${counts[k] || 0}</b><span>${k}</span></div>`).join('');
      document.getElementById('findings').innerHTML = (data.high_findings || []).map(f => `<tr><td class="${f.severity}">${f.severity}</td><td>${escapeHtml(f.title)}</td><td>${escapeHtml(f.file || '')}</td><td>${escapeHtml(f.status || '')}</td></tr>`).join('');
      document.getElementById('analyses').innerHTML = (data.latest_risk || []).map(a => `<tr><td>${escapeHtml(a.subject_id)}</td><td class="${a.level}">${a.level}</td><td>${a.score}</td><td>${escapeHtml((a.payload && a.payload.passport && a.payload.passport.summary) || '')}</td></tr>`).join('');
    }
    function escapeHtml(value) { return String(value).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;', "'": '&#039;'}[ch])); }
    load();
  </script>
</body>
</html>"""
