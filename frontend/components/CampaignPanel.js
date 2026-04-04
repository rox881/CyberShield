// CampaignPanel.js — full campaign intelligence dashboard

const CampaignPanel = (() => {

  const API = "http://localhost:8000";

  const ATTACK_ICONS = {
    credential_harvest: "🎣",
    bec:               "🏢",
    spear_phish:       "🎯",
    malware_delivery:  "💀",
    social_engineering:"🧠",
    ai_generated:      "🤖",
    unknown:           "❓",
  };

  const ATTACK_LABELS = {
    credential_harvest: "Credential Harvest",
    bec:               "BEC",
    spear_phish:       "Spear Phish",
    malware_delivery:  "Malware Delivery",
    social_engineering:"Social Engineering",
    ai_generated:      "AI-Generated",
    unknown:           "Unknown",
  };

  // ── State ───────────────────────────────────────────────────────────────
  let allCampaigns = [];
  let stats        = {};
  let selectedId   = null;
  let filterBrand  = "";
  let filterAttack = "";
  let sortBy       = "count";

  // ── Init ────────────────────────────────────────────────────────────────
  async function load() {
    const el = document.getElementById("campaigns-list");
    if (!el) return;

    el.innerHTML = _loadingHTML();

    try {
      const [campData, statsData] = await Promise.all([
        fetch(`${API}/campaigns`).then(r => r.json()),
        fetch(`${API}/campaigns/stats`).then(r => r.json()),
      ]);
      allCampaigns = campData.campaigns || [];
      stats        = statsData;
      render();
    } catch (e) {
      el.innerHTML = `
        <div style="text-align:center;padding:60px 20px;font-family:var(--mono);
                    font-size:12px;color:var(--muted)">
          Backend unreachable — make sure the server is running on port 8000.
        </div>`;
    }
  }

  // ── Render ──────────────────────────────────────────────────────────────
  function render() {
    const el = document.getElementById("campaigns-list");
    if (!el) return;

    const filtered = _applyFilters(allCampaigns);

    el.innerHTML = `
      ${_statsHeaderHTML()}
      ${_filtersHTML()}
      ${filtered.length === 0 ? _emptyHTML() : filtered.map(_campaignCardHTML).join("")}
    `;

    // Wire filter controls
    el.querySelector("#camp-filter-brand")?.addEventListener("input", e => {
      filterBrand = e.target.value; render();
    });
    el.querySelector("#camp-filter-attack")?.addEventListener("change", e => {
      filterAttack = e.target.value; render();
    });
    el.querySelector("#camp-sort")?.addEventListener("change", e => {
      sortBy = e.target.value; render();
    });

    // Wire card expand buttons
    el.querySelectorAll(".camp-expand-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const id = btn.dataset.id;
        selectedId = selectedId === id ? null : id;
        render();
      });
    });

    // Wire timeline buttons
    el.querySelectorAll(".camp-timeline-btn").forEach(btn => {
      btn.addEventListener("click", () => loadTimeline(btn.dataset.id));
    });

    // Wire similar button
    el.querySelectorAll(".camp-similar-btn").forEach(btn => {
      btn.addEventListener("click", () => loadSimilar(btn.dataset.id));
    });
  }

  // ── Stats header ────────────────────────────────────────────────────────
  function _statsHeaderHTML() {
    const breakdown = stats.attack_breakdown || {};
    const topAttack = Object.entries(breakdown).sort((a,b)=>b[1]-a[1])[0];
    return `
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px">
        ${_statCell(stats.total_campaigns || 0, "Campaigns", "")}
        ${_statCell(stats.total_emails || 0, "Emails tracked", "")}
        ${_statCell(stats.unique_brands || 0, "Brands targeted", "")}
        ${_statCell(
          topAttack ? `${ATTACK_ICONS[topAttack[0]]||""}` : "—",
          "Top attack type",
          topAttack ? ATTACK_LABELS[topAttack[0]] : "none"
        )}
      </div>
    `;
  }

  function _statCell(val, label, sub) {
    return `
      <div style="background:var(--panel);border:1px solid var(--border);padding:14px;text-align:center">
        <div style="font-family:var(--mono);font-size:22px;font-weight:500;color:var(--accent)">${val}</div>
        <div style="font-family:var(--mono);font-size:10px;color:var(--muted);margin-top:3px">${label}</div>
        ${sub ? `<div style="font-size:10px;color:var(--text);margin-top:2px">${sub}</div>` : ""}
      </div>`;
  }

  // ── Filters ─────────────────────────────────────────────────────────────
  function _filtersHTML() {
    const attackTypes = [...new Set(allCampaigns.map(c => c.attack_type).filter(Boolean))];
    return `
      <div style="display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap">
        <input id="camp-filter-brand" type="text" value="${filterBrand}"
          placeholder="Filter by brand…"
          style="flex:1;min-width:120px;background:var(--bg);border:1px solid var(--border);
                 color:var(--text);font-family:var(--mono);font-size:11px;padding:8px 12px;outline:none">
        <select id="camp-filter-attack"
          style="background:var(--bg);border:1px solid var(--border);color:var(--text);
                 font-family:var(--mono);font-size:11px;padding:8px 12px">
          <option value="">All attack types</option>
          ${attackTypes.map(t=>`<option value="${t}" ${filterAttack===t?"selected":""}>${ATTACK_LABELS[t]||t}</option>`).join("")}
        </select>
        <select id="camp-sort"
          style="background:var(--bg);border:1px solid var(--border);color:var(--text);
                 font-family:var(--mono);font-size:11px;padding:8px 12px">
          <option value="count"     ${sortBy==="count"?"selected":""}>Sort: Email count</option>
          <option value="avg_score" ${sortBy==="avg_score"?"selected":""}>Sort: Avg score</option>
          <option value="velocity"  ${sortBy==="velocity"?"selected":""}>Sort: Velocity</option>
          <option value="last_seen" ${sortBy==="last_seen"?"selected":""}>Sort: Last seen</option>
        </select>
      </div>`;
  }

  // ── Campaign card ────────────────────────────────────────────────────────
  function _campaignCardHTML(c) {
    const expanded  = selectedId === c.id;
    const isActive  = c.is_active;
    const scoreColor = c.avg_score >= 70 ? "var(--danger)"
                     : c.avg_score >= 40 ? "var(--warn)" : "var(--safe)";

    return `
      <div style="background:var(--panel);border:1px solid var(--border);
                  border-left:3px solid ${scoreColor};margin-bottom:10px">
        <!-- Card header (always visible) -->
        <div style="padding:14px 16px;display:flex;align-items:flex-start;gap:14px;cursor:pointer"
             class="camp-expand-btn" data-id="${c.id}">

          <!-- Attack icon -->
          <div style="width:38px;height:38px;border-radius:8px;flex-shrink:0;
                      background:rgba(255,255,255,0.04);border:1px solid var(--border);
                      display:flex;align-items:center;justify-content:center;font-size:18px">
            ${ATTACK_ICONS[c.attack_type]||"❓"}
          </div>

          <!-- Main info -->
          <div style="flex:1;min-width:0">
            <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:4px">
              <span style="font-weight:600;color:#fff;font-size:14px">
                ${c.brand_target ? `${c.brand_target} — ` : ""}${ATTACK_LABELS[c.attack_type]||"Unknown"}
              </span>
              ${isActive
                ? `<span style="font-family:var(--mono);font-size:9px;padding:2px 7px;
                        border-radius:10px;background:rgba(29,158,117,0.15);
                        color:var(--safe);border:1px solid rgba(29,158,117,0.3)">ACTIVE</span>`
                : `<span style="font-family:var(--mono);font-size:9px;padding:2px 7px;
                        border-radius:10px;background:rgba(74,85,104,0.2);color:var(--muted)">DORMANT</span>`}
            </div>
            <div style="font-family:var(--mono);font-size:11px;color:var(--muted);
                        overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
              "${c.sample_subject}"
            </div>
          </div>

          <!-- Stats pills -->
          <div style="display:flex;flex-direction:column;align-items:flex-end;gap:4px;flex-shrink:0">
            <span style="font-family:var(--mono);font-size:20px;font-weight:500;color:${scoreColor}">${c.avg_score}</span>
            <span style="font-family:var(--mono);font-size:9px;color:var(--muted)">avg score</span>
            <span style="font-family:var(--mono);font-size:11px;color:var(--accent)">${c.count} emails</span>
            <span style="font-family:var(--mono);font-size:9px;color:var(--muted)">${c.velocity}/day</span>
          </div>
        </div>

        <!-- Expanded detail -->
        ${expanded ? _expandedHTML(c) : ""}
      </div>`;
  }

  // ── Expanded panel ───────────────────────────────────────────────────────
  function _expandedHTML(c) {
    const scoreColor = c.avg_score >= 70 ? "var(--danger)"
                     : c.avg_score >= 40 ? "var(--warn)" : "var(--safe)";
    return `
      <div style="border-top:1px solid var(--border);padding:16px;background:rgba(0,0,0,0.2)">

        <!-- Metrics row -->
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:14px">
          ${_metricCell("Peak score", c.peak_score, scoreColor)}
          ${_metricCell("Emails/day", c.velocity, "var(--accent)")}
          ${_metricCell("Duration",
            _duration(c.first_seen, c.last_seen), "var(--text)")}
        </div>

        <!-- Subject templates -->
        ${c.subject_templates?.length ? `
          <div style="margin-bottom:12px">
            <div style="font-family:var(--mono);font-size:9px;letter-spacing:2px;
                        color:var(--accent);margin-bottom:6px">SUBJECT TEMPLATES</div>
            ${c.subject_templates.map(t=>`
              <div style="font-family:var(--mono);font-size:11px;color:var(--text);
                          padding:6px 10px;background:var(--bg);border:1px solid var(--border);
                          margin-bottom:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
                "${t}"
              </div>`).join("")}
          </div>` : ""}

        <!-- Sender domains -->
        ${c.sender_domains?.length ? `
          <div style="margin-bottom:12px">
            <div style="font-family:var(--mono);font-size:9px;letter-spacing:2px;
                        color:var(--accent);margin-bottom:6px">SENDER DOMAINS</div>
            <div style="display:flex;flex-wrap:wrap;gap:6px">
              ${c.sender_domains.map(d=>`
                <span style="font-family:var(--mono);font-size:10px;padding:3px 8px;
                             background:rgba(226,75,74,0.1);color:var(--danger);
                             border:1px solid rgba(226,75,74,0.2)">${d}</span>`).join("")}
            </div>
          </div>` : ""}

        <!-- Score bar -->
        <div style="margin-bottom:14px">
          <div style="display:flex;justify-content:space-between;margin-bottom:4px">
            <span style="font-family:var(--mono);font-size:9px;color:var(--muted)">AVG RISK SCORE</span>
            <span style="font-family:var(--mono);font-size:11px;color:${scoreColor}">${c.avg_score}/100</span>
          </div>
          <div style="background:var(--border);border-radius:3px;height:4px;overflow:hidden">
            <div style="width:${c.avg_score}%;height:100%;background:${scoreColor};
                        border-radius:3px;transition:width 0.6s"></div>
          </div>
        </div>

        <!-- Dates -->
        <div style="display:flex;justify-content:space-between;
                    font-family:var(--mono);font-size:10px;color:var(--muted);margin-bottom:14px">
          <span>First seen: ${_fmtDate(c.first_seen)}</span>
          <span>Last seen: ${_fmtDate(c.last_seen)}</span>
        </div>

        <!-- Action buttons -->
        <div style="display:flex;gap:8px">
          <button class="camp-timeline-btn" data-id="${c.id}"
            style="flex:1;padding:7px;background:var(--bg);border:1px solid var(--border);
                   color:var(--muted);font-family:var(--mono);font-size:10px;cursor:pointer;
                   transition:all 0.15s"
            onmouseover="this.style.borderColor='var(--accent)';this.style.color='var(--accent)'"
            onmouseout="this.style.borderColor='var(--border)';this.style.color='var(--muted)'">
            📈 Score Timeline
          </button>
          <button class="camp-similar-btn" data-id="${c.id}"
            style="flex:1;padding:7px;background:var(--bg);border:1px solid var(--border);
                   color:var(--muted);font-family:var(--mono);font-size:10px;cursor:pointer;
                   transition:all 0.15s"
            onmouseover="this.style.borderColor='var(--accent)';this.style.color='var(--accent)'"
            onmouseout="this.style.borderColor='var(--border)';this.style.color='var(--muted)'">
            🔗 Find Similar
          </button>
        </div>

        <!-- Timeline / similar placeholder -->
        <div id="camp-detail-${c.id}" style="margin-top:12px"></div>
      </div>`;
  }

  function _metricCell(label, val, color) {
    return `
      <div style="text-align:center;padding:10px;background:var(--bg);border:1px solid var(--border)">
        <div style="font-family:var(--mono);font-size:16px;font-weight:500;color:${color}">${val}</div>
        <div style="font-family:var(--mono);font-size:9px;color:var(--muted);margin-top:2px">${label}</div>
      </div>`;
  }

  // ── Timeline loader ──────────────────────────────────────────────────────
  async function loadTimeline(id) {
    const el = document.getElementById(`camp-detail-${id}`);
    if (!el) return;
    el.innerHTML = `<div style="font-family:var(--mono);font-size:11px;color:var(--muted);
                                padding:10px;text-align:center">Loading…</div>`;
    try {
      const data = await fetch(`${API}/campaigns/${id}/timeline`).then(r=>r.json());
      const points = data.timeline || [];
      if (!points.length) { el.innerHTML = ""; return; }

      // Simple ASCII-style bar chart
      const max = Math.max(...points.map(p=>p.score), 1);
      el.innerHTML = `
        <div style="background:var(--bg);border:1px solid var(--border);padding:12px">
          <div style="font-family:var(--mono);font-size:9px;letter-spacing:2px;
                      color:var(--accent);margin-bottom:10px">SCORE TIMELINE</div>
          <div style="display:flex;align-items:flex-end;gap:3px;height:60px">
            ${points.map(p => {
              const h = Math.max(4, (p.score/max)*56);
              const c = p.score>=70?"var(--danger)":p.score>=40?"var(--warn)":"var(--safe)";
              return `<div title="Email ${p.index}: ${p.score}"
                           style="flex:1;height:${h}px;background:${c};
                                  min-width:4px;border-radius:2px 2px 0 0;
                                  transition:height 0.4s"></div>`;
            }).join("")}
          </div>
          <div style="display:flex;justify-content:space-between;
                      font-family:var(--mono);font-size:9px;color:var(--muted);margin-top:4px">
            <span>#1</span><span>#${points.length}</span>
          </div>
        </div>`;
    } catch(_) {
      el.innerHTML = `<div style="font-family:var(--mono);font-size:11px;
                                  color:var(--muted);padding:10px">Timeline unavailable.</div>`;
    }
  }

  // ── Similar loader ───────────────────────────────────────────────────────
  async function loadSimilar(id) {
    const el = document.getElementById(`camp-detail-${id}`);
    if (!el) return;
    el.innerHTML = `<div style="font-family:var(--mono);font-size:11px;color:var(--muted);
                                padding:10px;text-align:center">Searching…</div>`;
    try {
      const data   = await fetch(`${API}/campaigns/${id}/similar`).then(r=>r.json());
      const similar = data.similar || [];
      if (!similar.length) {
        el.innerHTML = `<div style="font-family:var(--mono);font-size:11px;
                                    color:var(--muted);padding:10px">No similar campaigns found.</div>`;
        return;
      }
      el.innerHTML = `
        <div style="background:var(--bg);border:1px solid var(--border);padding:12px">
          <div style="font-family:var(--mono);font-size:9px;letter-spacing:2px;
                      color:var(--accent);margin-bottom:10px">SIMILAR CAMPAIGNS</div>
          ${similar.map(s=>`
            <div style="display:flex;align-items:center;gap:10px;padding:8px 0;
                        border-bottom:1px solid var(--border);font-family:var(--mono);font-size:11px">
              <span style="color:var(--text);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
                ${ATTACK_ICONS[s.attack_type]||""} ${s.brand_target||""} — ${s.sample_subject||""}
              </span>
              <span style="color:var(--accent);flex-shrink:0">${(s.similarity*100).toFixed(0)}% match</span>
              <span style="color:var(--muted);flex-shrink:0">${s.count} emails</span>
            </div>`).join("")}
        </div>`;
    } catch(_) {
      el.innerHTML = `<div style="font-family:var(--mono);font-size:11px;
                                  color:var(--muted);padding:10px">Search failed.</div>`;
    }
  }

  // ── Helpers ──────────────────────────────────────────────────────────────
  function _applyFilters(campaigns) {
    let result = [...campaigns];
    if (filterBrand)  result = result.filter(c => c.brand_target?.toLowerCase().includes(filterBrand.toLowerCase()));
    if (filterAttack) result = result.filter(c => c.attack_type === filterAttack);
    if (sortBy === "avg_score") result.sort((a,b)=>b.avg_score-a.avg_score);
    else if (sortBy === "velocity") result.sort((a,b)=>b.velocity-a.velocity);
    else if (sortBy === "last_seen") result.sort((a,b)=>b.last_seen.localeCompare(a.last_seen));
    else result.sort((a,b)=>b.count-a.count);
    return result;
  }

  function _emptyHTML() {
    return `
      <div style="text-align:center;padding:60px 20px">
        <div style="font-size:32px;margin-bottom:12px">🔍</div>
        <div style="font-family:var(--mono);font-size:12px;color:var(--muted)">
          No campaigns detected yet.<br>
          Scan multiple similar phishing emails to trigger clustering.
        </div>
        ${stats.singletons_pending>0
          ? `<div style="margin-top:10px;font-family:var(--mono);font-size:10px;color:var(--accent)">
               ${stats.singletons_pending} singleton(s) pending a match
             </div>`
          : ""}
      </div>`;
  }

  function _loadingHTML() {
    return `<div style="text-align:center;padding:60px 20px;font-family:var(--mono);
                        font-size:12px;color:var(--muted)">Loading campaigns…</div>`;
  }

  function _fmtDate(iso) {
    try { return new Date(iso).toLocaleDateString(); } catch(_) { return iso; }
  }

  function _duration(start, end) {
    try {
      const ms   = new Date(end) - new Date(start);
      const days = Math.floor(ms/86400000);
      if (days === 0) return "<1 day";
      return `${days}d`;
    } catch(_) { return "—"; }
  }

  return { load };
})();
