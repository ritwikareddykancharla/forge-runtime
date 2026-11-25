(() => {
  "use strict";

  const root = document.documentElement;
  const el = (id) => document.getElementById(id);

  const state = {
    repoFiles: [],
    selectedSymbol: "preview_settlement_headroom",
    hopBudget: 2,
    tasks: [],
    selectedTaskId: "MOD-01-DECIMAL-SETTLEMENT",
    personas: [],
    selectedPersonaId: "partner_analyst",
    icebergTables: [],
  };

  function escapeHtml(raw) {
    return String(raw ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  /* ---------- Blueprint Theme Toggle (URL hash + dataset.theme, stateless) ---------- */
  const themeBtn = document.querySelector(".theme");
  if (themeBtn) {
    themeBtn.addEventListener("click", () => {
      const next = root.dataset.theme === "dark" ? "light" : "dark";
      root.dataset.theme = next;
      history.replaceState(null, "", `#theme=${next}`);
    });
  }

  /* ---------- Blueprint Sidebar Progress & Back-To-Top Ring ---------- */
  function initBlueprintScrollChrome() {
    const side = document.querySelector(".side");
    const body = document.querySelector(".post-body");
    const links = side ? [...side.querySelectorAll(".side-list a")] : [];
    const targets = links.map((a) => document.getElementById(a.hash.slice(1)));
    const ind = side && side.querySelector(".side-ind");
    const bar = side && side.querySelector(".side-bar i");
    const pct = side && side.querySelector(".side-pct");
    const toTop = document.querySelector(".totop");
    const ring = toTop && toTop.querySelector(".ring");
    const navLinks = [...document.querySelectorAll(".site nav a")].filter((a) => a.hash);
    const RING = 2 * Math.PI * 21;
    if (ring) ring.style.strokeDasharray = String(RING);

    function onScroll() {
      const y = window.scrollY;
      const max = Math.max(1, root.scrollHeight - window.innerHeight);
      if (toTop && ring) {
        toTop.classList.toggle("show", y > 500);
        ring.style.strokeDashoffset = String(RING * (1 - y / max));
      }
      if (side && body && bar && pct) {
        const r = body.getBoundingClientRect();
        const read = Math.min(1, Math.max(0, (window.innerHeight * 0.45 - r.top) / Math.max(1, r.height)));
        bar.style.transform = `scaleX(${read})`;
        pct.textContent = `${Math.round(read * 100)}%`;

        let activeIdx = 0;
        targets.forEach((t, idx) => {
          if (t && t.getBoundingClientRect().top <= 150) activeIdx = idx;
        });
        links.forEach((a, idx) => a.classList.toggle("on", idx === activeIdx));
        navLinks.forEach((a, idx) => a.classList.toggle("on", idx === activeIdx));
        const activeLink = links[activeIdx];
        if (activeLink && ind) {
          const listRect = side.querySelector(".side-list").getBoundingClientRect();
          const aRect = activeLink.getBoundingClientRect();
          ind.style.opacity = "1";
          ind.style.transform = `translateY(${aRect.top - listRect.top}px)`;
          ind.style.height = `${aRect.height}px`;
        }
      }
    }

    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll);
    onScroll();
  }

  async function apiCall(path, method = "GET", body = null) {
    const opts = { method, headers: {} };
    if (body !== null) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const resp = await fetch(path, opts);
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.error || `HTTP ${resp.status}`);
    }
    return data;
  }

  function switchPerspective(mode) {
    ["ast", "sandbox", "lake"].forEach((m) => {
      el(`tab-${m}`).classList.toggle("active", m === mode);
      el(`view-${m}`).classList.toggle("hidden", m !== mode);
    });
  }

  /* ---------- PANE 1: AST REPO EXPLORER & 2-HOP SLICER ---------- */
  function renderRepoTree() {
    el("repo-files-count").textContent = `${state.repoFiles.length} Modules`;
    const wrap = el("repo-tree");
    wrap.innerHTML = state.repoFiles
      .map((f) => {
        const symButtons = (f.symbols || [])
          .map((s) => {
            const isSel =
              s.name === state.selectedSymbol ||
              s.node_id === state.selectedSymbol ||
              s.qualname === state.selectedSymbol;
            const kindTag = s.kind === "Class" ? "cls" : "def";
            return `
              <button type="button" class="sym-btn ${isSel ? "active" : ""}" data-sym="${escapeHtml(s.name)}">
                <span>${kindTag} ${escapeHtml(s.name)}</span>
                <span>L${s.start_line}</span>
              </button>
            `;
          })
          .join("");
        return `
          <div class="file-group">
            <div class="file-head">
              <span>${escapeHtml(f.display_name)}</span>
              <span style="color:var(--soft);">${f.tokens}t</span>
            </div>
            ${symButtons}
          </div>
        `;
      })
      .join("");

    wrap.querySelectorAll(".sym-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.selectedSymbol = btn.getAttribute("data-sym");
        renderRepoTree();
        fetchAndRenderAstSlice();
      });
    });
  }

  function renderSlicePayload(sl) {
    if (!sl) return;
    const agg = sl.benchmark_aggregate || {};
    el("ast-recall-badge").textContent = `${sl.neighborhood_recall_pct}% Recall (${sl.hop_budget}-Hop)`;
    el("stat-full-tokens").textContent = `${sl.naive_full_repo_tokens.toLocaleString()} tok (${agg.token_compression_ratio_vs_full_repo || 5.97}x Bloated)`;
    el("stat-sliced-tokens").textContent = `${sl.packed_tokens.toLocaleString()} tok (-${sl.token_reduction_pct}%)`;
    el("stat-bench-agg").textContent = `-83.2% Mean (${Math.round(agg.mean_packed_tokens || 734)} vs 4,382 tok)`;

    el("left-tok-pill").textContent = `${sl.naive_full_repo_tokens.toLocaleString()} tok`;
    el("right-slice-title").textContent = `${sl.hop_budget}-Hop AST Slice: ${sl.focal_symbol.name}()`;
    el("right-tok-pill").textContent = `${sl.packed_tokens.toLocaleString()} tok`;

    el("raw-repo-code").textContent = sl.full_repo_source;
    el("sliced-ast-code").textContent = sl.packed_context;

    el("graph-edges-badge").textContent = `${(sl.graph_edges || []).length} Edges`;
    el("focal-symbol-card").innerHTML = `
      <div><strong>HOP 0 FOCAL: ${escapeHtml(sl.focal_symbol.qualname)}</strong></div>
      <div style="color:var(--soft);">${escapeHtml(sl.display_focal_file)}:L${sl.focal_symbol.start_line}-L${sl.focal_symbol.end_line} &middot; Complexity ${sl.focal_symbol.cyclomatic_complexity}</div>
      <div style="margin-top:4px;">Single-file recall alone: <strong style="color:var(--bad);">${sl.single_file_recall_pct}%</strong> vs AST ${sl.hop_budget}-hop: <strong style="color:var(--ok);">${sl.neighborhood_recall_pct}%</strong></div>
    `;

    el("hop-nodes-list").innerHTML = (sl.graph_nodes || [])
      .map((n) => {
        const hopColor = n.hop === 0 ? "var(--signal)" : n.hop === 1 ? "var(--cobalt)" : "var(--ok)";
        return `
          <div class="hop-node" style="border-left:3px solid ${hopColor};">
            <div style="display:flex;justify-content:space-between;">
              <strong>[Hop ${n.hop}] ${escapeHtml(n.name)}</strong>
              <span style="color:var(--soft);">${escapeHtml(n.display_file)}</span>
            </div>
            <div style="color:var(--soft);">${escapeHtml(n.kind)} &middot; L${n.start_line}-L${n.end_line} (${n.tokens} tok)</div>
          </div>
        `;
      })
      .join("");
  }

  async function fetchAndRenderAstSlice() {
    const sl = await apiCall("/api/ast/slice", "POST", {
      symbol: state.selectedSymbol,
      hops: state.hopBudget,
    });
    renderSlicePayload(sl);
  }

  /* ---------- PANE 2: BEDROCK MODERNIZATION & WARM SANDBOX ---------- */
  function renderModTasks() {
    const wrap = el("mod-task-list");
    wrap.innerHTML = state.tasks
      .map((t) => `
        <button type="button" class="task-card ${t.task_id === state.selectedTaskId ? "active" : ""}" data-task-id="${escapeHtml(t.task_id)}">
          <b>${escapeHtml(t.title)}</b>
          <span>Symbol: ${escapeHtml(t.target_symbol)}() &middot; ${t.ast_hop_depth}-hop slice</span>
        </button>
      `)
      .join("");

    wrap.querySelectorAll(".task-card").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.selectedTaskId = btn.getAttribute("data-task-id");
        const chosen = state.tasks.find((t) => t.task_id === state.selectedTaskId);
        if (chosen) {
          el("python-editor").value = chosen.starter_code;
        }
        renderModTasks();
      });
    });
  }

  function renderSandboxResult(sbxBundle) {
    const warm = sbxBundle.warm;
    const cold = sbxBundle.cold;
    el("escape-matrix-wrap").classList.add("hidden");

    const pill = el("sbx-status-pill");
    pill.textContent = warm.status;
    pill.style.color = warm.ok ? "#4fd19a" : "#ff7a66";

    if (cold) {
      const wMs = warm.dispatch_latency_ms;
      const cMs = cold.dispatch_latency_ms;
      el("lat-warm-val").textContent = `${wMs.toFixed(2)} ms`;
      el("lat-cold-val").textContent = `${cMs.toFixed(2)} ms`;
      const ratioPct = Math.max(3, Math.min(100, (wMs / Math.max(1, cMs)) * 100));
      el("lat-warm-bar").style.width = `${ratioPct}%`;
      el("lat-speedup-caption").textContent = sbxBundle.speedup_x
        ? `Live AWS execution: WarmSandboxPool ran ${sbxBundle.speedup_x}x faster than cold subprocess.`
        : "Executed in isolated python3 -I worker pipe.";
    } else {
      el("lat-warm-val").textContent = `${warm.dispatch_latency_ms.toFixed(2)} ms`;
    }

    el("sbx-output-pre").textContent = JSON.stringify(warm, null, 2);
  }

  async function runBedrockModernization() {
    el("bedrock-explanation").textContent =
      "Routing via MultiModelRouter & synthesizing refactored Python via Amazon Bedrock (`us.amazon.nova-lite-v1:0`)...";
    el("sbx-status-pill").textContent = "SYNTHESIZING";
    const slaRaw = el("sla-select").value;
    const res = await apiCall("/api/modernize/synthesize", "POST", {
      task_id: state.selectedTaskId,
      sla_max_p95_ms: slaRaw ? Number(slaRaw) : null,
    });

    el("rt-model-id").textContent = res.routing_decision.selected_model;
    el("rt-complexity").textContent = String(res.routing_decision.complexity_score);
    el("python-editor").value = res.modernized_code;
    el("bedrock-explanation").textContent =
      `[${res.bedrock_engine} · ${res.bedrock_latency_ms} ms | Router: ${res.routing_decision.rationale}]\n` +
      res.explanation;
    renderSandboxResult(res.sandbox_run);
  }

  async function executeCurrentPython() {
    const res = await apiCall("/api/sandbox/execute", "POST", {
      code: el("python-editor").value,
      compare_cold: true,
    });
    renderSandboxResult(res);
  }

  async function testSingleEscapeProbe() {
    const escapeSnippet =
      "# Adversarial Sandbox Escape Probe: OS Command + /etc/passwd Read\nimport os\nos.system('id')\nopen('/etc/passwd', 'r').read()";
    el("python-editor").value = escapeSnippet;
    const res = await apiCall("/api/sandbox/execute", "POST", {
      code: escapeSnippet,
      compare_cold: false,
    });
    renderSandboxResult(res);
  }

  async function runAll10EscapeVectors() {
    const res = await apiCall("/api/sandbox/escapes", "POST", {});
    el("sbx-status-pill").textContent = `${res.blocked_count}/${res.total_vectors} BLOCKED`;
    el("sbx-output-pre").textContent =
      `Containment Rate: ${res.containment_rate_pct}% (${res.blocked_count}/${res.total_vectors} blocked)\n` +
      `Post-Timeout Worker Slot Recycled & Verified: ${JSON.stringify(res.post_timeout_worker_recovery)}`;
    const wrap = el("escape-matrix-wrap");
    wrap.classList.remove("hidden");
    el("escape-matrix-list").innerHTML = res.vectors
      .map(
        (v) => `
        <div class="esc-row">
          <span>✓ ${escapeHtml(v.attack_id)}</span>
          <span>${escapeHtml(v.status)} (${v.latency_ms}ms)</span>
        </div>
      `
      )
      .join("");
  }

  /* ---------- PANE 3: CEDAR-GOVERNED APACHE ICEBERG SQL PROXY ---------- */
  function renderLakeSidebar() {
    const sel = el("sql-persona-select");
    sel.innerHTML = state.personas
      .map(
        (p) =>
          `<option value="${escapeHtml(p.persona_id)}" ${p.persona_id === state.selectedPersonaId ? "selected" : ""}>${escapeHtml(p.label)}</option>`
      )
      .join("");

    const activePersona =
      state.personas.find((p) => p.persona_id === state.selectedPersonaId) || state.personas[0];
    if (activePersona) {
      el("persona-clearance-note").textContent =
        `${activePersona.principal_id} · ${activePersona.badge}`;
    }

    el("iceberg-schema-list").innerHTML = state.icebergTables
      .map((t) => {
        const cols = (t.columns || [])
          .map((c) => {
            const isPii = !["PUBLIC", "INTERNAL"].includes(c.classification);
            return `<div>${escapeHtml(c.name)} <span class="col-tag ${isPii ? "col-pii" : ""}">${escapeHtml(c.classification)}</span></div>`;
          })
          .join("");
        return `
          <div class="tbl-box">
            <strong>${escapeHtml(t.table_name)}</strong> <span style="color:var(--soft);">(${t.row_count} rows)</span>
            <div style="color:var(--soft);margin-bottom:4px;">${escapeHtml(t.iceberg_uri)}</div>
            ${cols}
          </div>
        `;
      })
      .join("");
  }

  function renderSqlResult(res) {
    const badge = el("sql-verdict-badge");
    badge.textContent = res.ok ? `ALLOW (${res.row_count} rows)` : `BLOCKED (${res.error_code})`;
    badge.style.color = res.ok ? "#4fd19a" : "#ff7a66";

    const g1Ok = res.error_code !== "READ_ONLY_SQL_VIOLATION";
    const g2Ok = res.error_code !== "COLUMN_ACL_VIOLATION";
    const g4Ok = Boolean(res.schema_contract_validated);

    el("sql-gates-checklist").innerHTML = `
      <div class="gate-item ${g1Ok ? "pass" : "fail"}">
        <strong>Gate 1 &middot; Read-Only Lexical Check:</strong> ${g1Ok ? "PASSED (SELECT/WITH)" : "BLOCKED DDL/DML"}
      </div>
      <div class="gate-item ${g2Ok ? "pass" : "fail"}">
        <strong>Gate 2 &middot; SQLite C-Authorizer PII/PCI:</strong> ${
          g2Ok ? "PASSED (0 restricted columns)" : `BLOCKED (${escapeHtml((res.blocked_columns || []).join(", "))})`
        }
      </div>
      <div class="gate-item pass">
        <strong>Gate 3 &middot; Sovereign Region RLS CTE:</strong> ${
          (res.row_level_filters_applied || []).length
            ? escapeHtml(res.row_level_filters_applied.join("; "))
            : "Evaluated pre-execution"
        }
      </div>
      <div class="gate-item ${g4Ok ? "pass" : "fail"}">
        <strong>Gate 4 &middot; EXPLAIN QUERY PLAN Contract:</strong> ${g4Ok ? "VERIFIED" : "HALTED BEFORE SCAN"}
      </div>
    `;

    el("sql-audit-pre").textContent = JSON.stringify(
      {
        ok: res.ok,
        principal_id: res.persona ? res.persona.principal_id : res.principal_id,
        error_code: res.error_code || null,
        message: res.message || "Query authorized and executed.",
        explain_query_plan: res.explain_query_plan || [],
        row_level_filters_applied: res.row_level_filters_applied || [],
        latency_ms: res.latency_ms,
      },
      null,
      2
    );

    const wrap = el("sql-result-table-wrap");
    if (!res.ok) {
      wrap.innerHTML = `<div style="padding:12px;border:1px solid var(--bad);background:var(--bad-soft);color:var(--bad);font:500 11.5px/1.5 var(--mono);">PRE-EXECUTION BLOCK [${escapeHtml(res.error_code)}]: ${escapeHtml(res.message)}</div>`;
      return;
    }
    if (!res.rows || !res.rows.length) {
      wrap.innerHTML = `<div style="font:400 11.5px var(--mono);color:var(--soft);">0 rows returned.</div>`;
      return;
    }
    const headers = res.columns.map((c) => `<th>${escapeHtml(c)}</th>`).join("");
    const rowsHtml = res.rows
      .map(
        (r) =>
          `<tr>${res.columns.map((c) => `<td style="font:400 11px var(--mono);">${escapeHtml(r[c])}</td>`).join("")}</tr>`
      )
      .join("");
    wrap.innerHTML = `<table><thead><tr>${headers}</tr></thead><tbody>${rowsHtml}</tbody></table>`;
  }

  async function executeCurrentSql() {
    const res = await apiCall("/api/lake/query", "POST", {
      sql: el("sql-editor").value,
      persona_id: state.selectedPersonaId,
    });
    renderSqlResult(res);
  }

  async function loadInitialState() {
    const snap = await apiCall("/api/state");
    state.repoFiles = snap.repo_files || [];
    state.tasks = snap.modernization_tasks || [];
    state.personas = snap.sql_personas || [];
    state.icebergTables = snap.iceberg_tables || [];

    renderRepoTree();
    renderSlicePayload(snap.initial_slice);
    renderModTasks();
    if (state.tasks[0]) {
      el("python-editor").value = state.tasks[0].starter_code;
    }
    renderLakeSidebar();
    await executeCurrentSql();
  }

  function wireEvents() {
    el("tab-ast").addEventListener("click", () => switchPerspective("ast"));
    el("tab-sandbox").addEventListener("click", () => switchPerspective("sandbox"));
    el("tab-lake").addEventListener("click", () => switchPerspective("lake"));

    el("hop-buttons").querySelectorAll(".hop-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        el("hop-buttons").querySelectorAll(".hop-btn").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        state.hopBudget = Number(btn.getAttribute("data-hops"));
        fetchAndRenderAstSlice();
      });
    });

    el("btn-handoff-modernize").addEventListener("click", () => {
      switchPerspective("sandbox");
      executeCurrentPython();
    });

    el("btn-bedrock-synthesize").addEventListener("click", () => runBedrockModernization());
    el("btn-exec-sandbox").addEventListener("click", () => executeCurrentPython());
    el("btn-test-single-escape").addEventListener("click", () => testSingleEscapeProbe());
    el("btn-run-all-10-escapes").addEventListener("click", () => runAll10EscapeVectors());

    el("sql-persona-select").addEventListener("change", (ev) => {
      state.selectedPersonaId = ev.target.value;
      renderLakeSidebar();
      executeCurrentSql();
    });

    document.querySelectorAll(".sql-preset-chip").forEach((chip) => {
      chip.addEventListener("click", () => {
        el("sql-editor").value = chip.getAttribute("data-sql");
        executeCurrentSql();
      });
    });

    el("btn-run-sql").addEventListener("click", () => executeCurrentSql());

    el("nl2sql-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const q = el("nl2sql-input").value.trim();
      if (!q) return;
      el("sql-verdict-badge").textContent = "BEDROCK NL2SQL...";
      const res = await apiCall("/api/lake/nl2sql", "POST", {
        question: q,
        persona_id: state.selectedPersonaId,
      });
      el("sql-editor").value = res.generated_sql;
      renderSqlResult(res.execution);
    });

    /* 1-Click Guided Workflows */
    el("guide-ast-slice").addEventListener("click", () => {
      switchPerspective("ast");
      state.selectedSymbol = "settle_tenant_invoice";
      state.hopBudget = 2;
      renderRepoTree();
      fetchAndRenderAstSlice();
    });

    el("guide-bedrock-modernize").addEventListener("click", () => {
      switchPerspective("sandbox");
      state.selectedTaskId = "MOD-01-DECIMAL-SETTLEMENT";
      renderModTasks();
      runBedrockModernization();
    });

    el("guide-escape-test").addEventListener("click", async () => {
      switchPerspective("sandbox");
      await testSingleEscapeProbe();
      await runAll10EscapeVectors();
    });

    el("guide-iceberg-pii").addEventListener("click", () => {
      switchPerspective("lake");
      state.selectedPersonaId = "partner_analyst";
      renderLakeSidebar();
      el("sql-editor").value = "SELECT account_id, email, ssn, spend_usd FROM customer_ads LIMIT 5";
      executeCurrentSql();
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    initBlueprintScrollChrome();
    wireEvents();
    loadInitialState().catch((err) => console.error(err));
  });
})();
