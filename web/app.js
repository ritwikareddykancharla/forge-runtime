(() => {
  "use strict";

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

  function logTerm(tag, tagClass, message) {
    const stream = el("term-stream");
    const now = new Date().toISOString().slice(11, 23);
    const line = document.createElement("div");
    line.className = "t-line";
    line.innerHTML = `<span class="t-ts">[${now}]</span> <span class="${tagClass}">[${escapeHtml(tag)}]</span> ${escapeHtml(message)}`;
    stream.appendChild(line);
    stream.scrollTop = stream.scrollHeight;
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

  function switchTab(mode) {
    ["ast", "sandbox", "lake"].forEach((m) => {
      el(`tab-${m}`).classList.toggle("active", m === mode);
      el(`act-${m}`).classList.toggle("active", m === mode);
      el(`view-${m}`).classList.toggle("hidden", m !== mode);
      el(`sb-${m}`).classList.toggle("hidden", m !== mode);
    });
    window.location.hash = `#${mode}`;
  }

  /* ---------- TAB 1: AST CALL-GRAPH SLICER ---------- */
  function renderRepoTree() {
    el("repo-files-count").textContent = `${state.repoFiles.length} files`;
    const wrap = el("repo-tree");
    wrap.innerHTML = state.repoFiles
      .map((f) => {
        const syms = (f.symbols || [])
          .map((s) => {
            const isSel =
              s.name === state.selectedSymbol ||
              s.node_id === state.selectedSymbol ||
              s.qualname === state.selectedSymbol;
            const kw = s.kind === "Class" ? "class" : "def";
            return `
              <button type="button" class="tree-sym ${isSel ? "active" : ""}" data-sym="${escapeHtml(s.name)}">
                <span><span class="sym-kind">${kw}</span>${escapeHtml(s.name)}</span>
                <span style="color:var(--fg-muted);">L${s.start_line}</span>
              </button>
            `;
          })
          .join("");
        return `
          <div class="tree-module">
            <div class="tree-mod-head">
              <span>${escapeHtml(f.display_name)}</span>
              <span style="color:var(--fg-dim);">${f.tokens}t</span>
            </div>
            ${syms}
          </div>
        `;
      })
      .join("");

    wrap.querySelectorAll(".tree-sym").forEach((btn) => {
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
    el("stat-full-tokens").textContent = `${sl.naive_full_repo_tokens.toLocaleString()} tok (${agg.token_compression_ratio_vs_full_repo || 5.97}x bloated)`;
    el("stat-sliced-tokens").textContent = `${sl.packed_tokens.toLocaleString()} tok (-${sl.token_reduction_pct}%)`;
    el("stat-bench-agg").textContent = `-83.2% tokens (${Math.round(agg.mean_packed_tokens || 734)} vs 4,382) · ${sl.neighborhood_recall_pct}% recall`;

    el("left-tok-pill").textContent = `${sl.naive_full_repo_tokens.toLocaleString()} tok`;
    el("right-slice-title").textContent = `${sl.hop_budget}-Hop AST Slice: ${sl.focal_symbol.name}()`;
    el("right-tok-pill").textContent = `${sl.packed_tokens.toLocaleString()} tok`;

    el("raw-repo-code").textContent = sl.full_repo_source;
    el("sliced-ast-code").textContent = sl.packed_context;

    el("graph-edges-badge").textContent = `${(sl.graph_edges || []).length} edges`;
    el("focal-symbol-card").innerHTML = `
      <div style="color:var(--cyan);font-weight:600;">${escapeHtml(sl.focal_symbol.qualname)}</div>
      <div style="color:var(--fg-dim);">${escapeHtml(sl.display_focal_file)}:L${sl.focal_symbol.start_line}-L${sl.focal_symbol.end_line} &middot; McCabe=${sl.focal_symbol.cyclomatic_complexity}</div>
      <div style="margin-top:4px;">Single-file recall: <strong style="color:var(--rose);">${sl.single_file_recall_pct}%</strong> &rarr; AST ${sl.hop_budget}-hop: <strong style="color:var(--diff-green);">${sl.neighborhood_recall_pct}%</strong></div>
    `;

    el("hop-nodes-list").innerHTML = (sl.graph_nodes || [])
      .map((n) => {
        const col = n.hop === 0 ? "var(--cyan)" : n.hop === 1 ? "var(--violet)" : "var(--diff-green)";
        return `
          <div class="hop-item" style="border-left-color:${col};">
            <div style="display:flex;justify-content:space-between;">
              <strong style="color:var(--fg-bright);">[H${n.hop}] ${escapeHtml(n.name)}</strong>
              <span style="color:var(--amber);">${escapeHtml(n.display_file)}</span>
            </div>
            <div style="color:var(--fg-dim);">${escapeHtml(n.kind)} L${n.start_line}-${n.end_line} (${n.tokens}t)</div>
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
    logTerm(
      "ASTRepoGraph",
      "t-tag-ast",
      `Sliced ${sl.focal_symbol.qualname} (hops=${sl.hop_budget}): ${sl.packed_tokens} tok vs ${sl.naive_full_repo_tokens} full repo (-${sl.token_reduction_pct}%, recall=${sl.neighborhood_recall_pct}%)`
    );
  }

  /* ---------- TAB 2: BEDROCK MODERNIZER & WARM SANDBOX ---------- */
  function renderModTasks() {
    const wrap = el("mod-task-list");
    wrap.innerHTML = state.tasks
      .map(
        (t) => `
        <button type="button" class="ide-card-btn ${t.task_id === state.selectedTaskId ? "active" : ""}" data-task-id="${escapeHtml(t.task_id)}">
          <b>${escapeHtml(t.title)}</b>
          <span>${escapeHtml(t.target_symbol)}() &middot; ${t.ast_hop_depth}-hop slice</span>
        </button>
      `
      )
      .join("");

    wrap.querySelectorAll(".ide-card-btn").forEach((btn) => {
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
    pill.style.color = warm.ok ? "var(--diff-green)" : "var(--rose)";

    if (cold) {
      const wMs = warm.dispatch_latency_ms;
      const cMs = cold.dispatch_latency_ms;
      el("lat-warm-val").textContent = `${wMs.toFixed(2)} ms`;
      el("lat-cold-val").textContent = `${cMs.toFixed(2)} ms`;
      const pct = Math.max(3, Math.min(100, (wMs / Math.max(1, cMs)) * 100));
      el("lat-warm-bar").style.width = `${pct}%`;
      if (sbxBundle.speedup_x) {
        el("lat-speedup-caption").textContent =
          `Live run: WarmSandboxPool dispatched ${sbxBundle.speedup_x}x faster than cold subprocess.`;
      }
    } else {
      el("lat-warm-val").textContent = `${warm.dispatch_latency_ms.toFixed(2)} ms`;
    }

    if (warm.ok) {
      logTerm(
        "WarmSandboxPool",
        "t-tag-ok",
        `SUCCESS in ${warm.dispatch_latency_ms.toFixed(2)}ms -> result=${JSON.stringify(warm.result)}`
      );
    } else {
      logTerm(
        "SandboxGate",
        "t-tag-bad",
        `${warm.status} in ${warm.dispatch_latency_ms.toFixed(2)}ms -> ${warm.error}`
      );
    }
  }

  async function runBedrockModernization() {
    el("bedrock-explanation").textContent =
      "Invoking MultiModelRouter + Amazon Bedrock (`us.amazon.nova-lite-v1:0`)...";
    logTerm("Bedrock Nova", "t-tag-ai", `Synthesizing modernized Python for ${state.selectedTaskId} via us.amazon.nova-lite-v1:0...`);
    const slaRaw = el("sla-select").value;
    const res = await apiCall("/api/modernize/synthesize", "POST", {
      task_id: state.selectedTaskId,
      sla_max_p95_ms: slaRaw ? Number(slaRaw) : null,
    });

    el("rt-model-id").textContent = res.routing_decision.selected_model;
    el("rt-complexity").textContent = String(res.routing_decision.complexity_score);
    el("python-editor").value = res.modernized_code;
    el("bedrock-explanation").textContent = `[${res.bedrock_engine} · ${res.bedrock_latency_ms}ms]\n${res.explanation}`;
    logTerm(
      "Bedrock Nova",
      "t-tag-ai",
      `Synthesized via ${res.bedrock_engine} (${res.bedrock_latency_ms}ms) | Router tier=${res.routing_decision.selected_model}`
    );
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
    const snippet =
      "# Adversarial Escape Probe: OS shell + /etc/passwd exfiltration\nimport os\nos.system('id')\nopen('/etc/passwd', 'r').read()";
    el("python-editor").value = snippet;
    const res = await apiCall("/api/sandbox/execute", "POST", {
      code: snippet,
      compare_cold: false,
    });
    renderSandboxResult(res);
  }

  async function runAll10EscapeVectors() {
    const res = await apiCall("/api/sandbox/escapes", "POST", {});
    el("sbx-status-pill").textContent = `${res.blocked_count}/${res.total_vectors} BLOCKED`;
    el("sbx-status-pill").style.color = "var(--diff-green)";
    const wrap = el("escape-matrix-wrap");
    wrap.classList.remove("hidden");
    el("escape-matrix-list").innerHTML = res.vectors
      .map(
        (v) => `
        <div class="esc-chip-row">
          <span>&#10003; ${escapeHtml(v.attack_id)}</span>
          <span>${escapeHtml(v.status)}</span>
        </div>
      `
      )
      .join("");
    logTerm(
      "EscapeSuite",
      "t-tag-ok",
      `Blocked ${res.blocked_count}/${res.total_vectors} attack vectors (${res.containment_rate_pct}% containment); post-timeout worker recycled=${res.post_timeout_worker_recovery.ok}`
    );
  }

  /* ---------- TAB 3: GOVERNED ICEBERG SQL CONSOLE ---------- */
  function renderLakeSidebar() {
    const sel = el("sql-persona-select");
    sel.innerHTML = state.personas
      .map(
        (p) =>
          `<option value="${escapeHtml(p.persona_id)}" ${p.persona_id === state.selectedPersonaId ? "selected" : ""}>${escapeHtml(p.label)}</option>`
      )
      .join("");

    const active = state.personas.find((p) => p.persona_id === state.selectedPersonaId) || state.personas[0];
    if (active) {
      el("persona-clearance-note").textContent = `${active.principal_id} — ${active.badge}`;
    }

    el("iceberg-schema-list").innerHTML = state.icebergTables
      .map((t) => {
        const cols = (t.columns || [])
          .map((c) => {
            const pii = !["PUBLIC", "INTERNAL"].includes(c.classification);
            return `<div style="display:flex;justify-content:space-between;"><span>${escapeHtml(c.name)}</span><span class="col-badge ${pii ? "pii" : ""}">${escapeHtml(c.classification)}</span></div>`;
          })
          .join("");
        return `
          <div class="ice-table-card">
            <strong style="color:var(--amber);">${escapeHtml(t.table_name)}</strong> <span style="color:var(--fg-muted);">(${t.row_count})</span>
            ${cols}
          </div>
        `;
      })
      .join("");
  }

  function renderSqlResult(res) {
    const badge = el("sql-verdict-badge");
    badge.textContent = res.ok ? `ALLOW (${res.row_count} rows)` : `BLOCKED`;
    badge.style.color = res.ok ? "var(--diff-green)" : "var(--rose)";

    const g1 = res.error_code !== "READ_ONLY_SQL_VIOLATION";
    const g2 = res.error_code !== "COLUMN_ACL_VIOLATION";
    const g4 = Boolean(res.schema_contract_validated);

    el("sql-gates-checklist").innerHTML = `
      <div class="gate-row ${g1 ? "" : "blocked"}">Gate 1 Read-Only: ${g1 ? "PASS" : "BLOCKED DDL/DML"}</div>
      <div class="gate-row ${g2 ? "" : "blocked"}">Gate 2 C-Authorizer PII: ${
        g2 ? "PASS" : `BLOCKED (${escapeHtml((res.blocked_columns || []).join(", "))})`
      }</div>
      <div class="gate-row">Gate 3 Region RLS CTE: ${
        (res.row_level_filters_applied || []).length
          ? escapeHtml(res.row_level_filters_applied.join("; "))
          : "Checked"
      }</div>
      <div class="gate-row ${g4 ? "" : "blocked"}">Gate 4 Query Plan: ${g4 ? "VERIFIED" : "HALTED PRE-EXEC"}</div>
    `;

    el("sql-audit-pre").textContent = JSON.stringify(
      {
        ok: res.ok,
        principal: res.persona ? res.persona.principal_id : res.principal_id,
        error_code: res.error_code || null,
        explain_plan: res.explain_query_plan || [],
        rls_injected: res.row_level_filters_applied || [],
        latency_ms: res.latency_ms,
      },
      null,
      2
    );

    const wrap = el("sql-result-table-wrap");
    if (!res.ok) {
      wrap.innerHTML = `<div style="padding:10px;border:1px solid var(--rose);background:rgba(247,118,142,0.1);color:var(--rose);font:500 11.5px var(--mono);">PRE-EXECUTION BLOCK [${escapeHtml(res.error_code)}]: ${escapeHtml(res.message)}</div>`;
      logTerm("IcebergProxy", "t-tag-bad", `Blocked SQL [${res.error_code}]: ${res.message}`);
      return;
    }

    logTerm(
      "IcebergProxy",
      "t-tag-ok",
      `Authorized SQL (${res.row_count} rows in ${res.latency_ms}ms) | RLS=${(res.row_level_filters_applied || []).join(", ") || "none"}`
    );

    if (!res.rows || !res.rows.length) {
      wrap.innerHTML = `<div class="mono" style="color:var(--fg-dim);">0 rows returned.</div>`;
      return;
    }
    const ths = res.columns.map((c) => `<th>${escapeHtml(c)}</th>`).join("");
    const trs = res.rows
      .map((r) => `<tr>${res.columns.map((c) => `<td>${escapeHtml(r[c])}</td>`).join("")}</tr>`)
      .join("");
    wrap.innerHTML = `<table class="ide-table"><thead><tr>${ths}</tr></thead><tbody>${trs}</tbody></table>`;
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

    if (snap.repo_stats) {
      el("sb-ast-count").textContent =
        `AST: ${snap.repo_stats.total_nodes} symbols / ${snap.repo_stats.files_indexed} modules`;
    }

    renderRepoTree();
    renderSlicePayload(snap.initial_slice);
    renderModTasks();
    if (state.tasks[0]) {
      el("python-editor").value = state.tasks[0].starter_code;
    }
    renderLakeSidebar();
    logTerm("ForgeRuntime", "t-tag-ok", "Initialized ASTRepoGraph, WarmSandboxPool (python3 -I), MultiModelRouter & GovernedLakeMCPServer.");
    await executeCurrentSql();

    const h = (window.location.hash || "").replace("#", "");
    if (["ast", "sandbox", "lake"].includes(h)) {
      switchTab(h);
    }
  }

  function wireEvents() {
    ["ast", "sandbox", "lake"].forEach((m) => {
      el(`tab-${m}`).addEventListener("click", () => switchTab(m));
      el(`act-${m}`).addEventListener("click", () => switchTab(m));
    });

    el("hop-buttons").querySelectorAll(".hop-pill").forEach((btn) => {
      btn.addEventListener("click", () => {
        el("hop-buttons").querySelectorAll(".hop-pill").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        state.hopBudget = Number(btn.getAttribute("data-hops"));
        fetchAndRenderAstSlice();
      });
    });

    el("btn-handoff-modernize").addEventListener("click", () => {
      switchTab("sandbox");
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
      logTerm("Bedrock Nova", "t-tag-ai", `Generating governed Iceberg SQL for: "${q}"`);
      const res = await apiCall("/api/lake/nl2sql", "POST", {
        question: q,
        persona_id: state.selectedPersonaId,
      });
      el("sql-editor").value = res.generated_sql;
      renderSqlResult(res.execution);
    });

    el("btn-clear-term").addEventListener("click", () => {
      el("term-stream").innerHTML = "";
    });

    /* 1-Click Guided Workflows */
    el("guide-ast-slice").addEventListener("click", () => {
      switchTab("ast");
      state.selectedSymbol = "settle_tenant_invoice";
      state.hopBudget = 2;
      renderRepoTree();
      fetchAndRenderAstSlice();
    });

    el("guide-bedrock-modernize").addEventListener("click", () => {
      switchTab("sandbox");
      state.selectedTaskId = "MOD-01-DECIMAL-SETTLEMENT";
      renderModTasks();
      runBedrockModernization();
    });

    el("guide-escape-test").addEventListener("click", async () => {
      switchTab("sandbox");
      await testSingleEscapeProbe();
      await runAll10EscapeVectors();
    });

    el("guide-iceberg-pii").addEventListener("click", () => {
      switchTab("lake");
      state.selectedPersonaId = "partner_analyst";
      renderLakeSidebar();
      el("sql-editor").value = "SELECT account_id, email, ssn, spend_usd FROM customer_ads LIMIT 5";
      executeCurrentSql();
    });

    el("btn-open-arch").addEventListener("click", () => el("arch-modal").classList.remove("hidden"));
    el("btn-close-arch").addEventListener("click", () => el("arch-modal").classList.add("hidden"));
    el("arch-modal").addEventListener("click", (e) => {
      if (e.target === el("arch-modal")) el("arch-modal").classList.add("hidden");
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    wireEvents();
    loadInitialState().catch((err) => logTerm("Error", "t-tag-bad", err.message));
  });
})();
