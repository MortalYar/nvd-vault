// ---------- Tab: дашборд ----------

function setupDashboardTab() {
    const loadBtn = document.getElementById('dashboard-load-btn');
    loadBtn.addEventListener('click', loadDashboard);
}

async function loadDashboard() {

    const status = document.getElementById('dashboard-status');
    const content = document.getElementById('dashboard-content');
    const loadBtn = document.getElementById('dashboard-load-btn');

    if (!AppState.hasVault()) {
        status.textContent = 'Сначала открой vault во вкладке «Просмотр Vault».';
        content.style.display = 'none';
        return;
    }

    loadBtn.disabled = true;

    const r = await window.pywebview.api.get_dashboard_for_path(AppState.currentVaultPath);

    loadBtn.disabled = false;

    if (!r.ok) {
        status.textContent = 'Ошибка: ' + r.error;
        content.style.display = 'none';
        return;
    }

    const total = r.kpi.total_cves;
    status.textContent = total > 0
        ? `Vault содержит ${total} CVE. Последнее обновление: только что.`
        : 'Vault пуст.';
    content.style.display = 'block';

    renderKpi(r.kpi);
    await loadRemediationPlan();
    renderTierBars(r.tier_distribution);
    renderTopCves(r.top_cves);
    renderTopProducts(r.top_products);
    renderTopCwes(r.top_cwes);
    renderKevDeadlines(r.kev_deadlines);
    renderRansomware(r.ransomware_cves);
}

function renderKpi(kpi) {
    const grid = document.getElementById('kpi-grid');
    const cards = [];

    cards.push(vKpi('Всего CVE', kpi.total_cves, 'info',
        kpi.total_cves > 0 ? 'мониторинг базы' : 'пусто'));

    if (kpi.critical_now > 0) {
        const pct = Math.min(100, (kpi.critical_now / Math.max(1, kpi.total_cves)) * 100);
        cards.push(vKpi('Эксплуатируется', kpi.critical_now, 'critical',
            'CISA KEV — патчить срочно', pct, 'error'));
    }
    if (kpi.critical_likely > 0) {
        cards.push(vKpi('Вероятная эксплуатация', kpi.critical_likely, 'critical',
            'EPSS ≥ 0.7'));
    }
    if (kpi.ransomware_total > 0) {
        cards.push(vKpi('Ransomware', kpi.ransomware_total, 'critical',
            'известные кампании'));
    }
    if (kpi.kev_overdue > 0) {
        cards.push(vKpi('Просрочено CISA', kpi.kev_overdue, 'critical',
            'превышен дедлайн'));
    }
    if (kpi.kev_due_soon > 0) {
        cards.push(vKpi('Скоро дедлайн', kpi.kev_due_soon, 'warning',
            'в ближайшие 30 дней'));
    }
    if (kpi.high > 0) {
        const pct = Math.min(100, (kpi.high / Math.max(1, kpi.total_cves)) * 100);
        cards.push(vKpi('Высокий риск', kpi.high, 'info',
            'плановый патчинг', pct, 'warning'));
    }

    grid.innerHTML = cards.join('');
}

function vKpi(label, value, type, sub, progress, progressType) {
    const dotClass = type === 'critical' ? 'v-dot-error'
                   : type === 'warning' ? 'v-dot-warning'
                   : 'v-dot-info';

    const cardClass = type === 'critical' ? 'v-kpi-critical' : '';

    let progressHtml = '';
    if (progress !== undefined) {
        const pCls = progressType === 'error' ? 'v-progress-error'
                   : progressType === 'warning' ? 'v-progress-warning'
                   : 'v-progress-info';
        progressHtml = `
            <div class="v-kpi-progress">
                <div class="v-kpi-progress-bar ${pCls}" style="width: ${progress}%"></div>
            </div>
        `;
    }

    return `
        <div class="v-kpi-card ${cardClass}">
            <div class="v-kpi-label">
                <span>${escapeHtml(label)}</span>
                <span class="v-kpi-dot ${dotClass}"></span>
            </div>
            <div class="v-kpi-value">${value}</div>
            ${progressHtml}
            <div class="v-kpi-sub">${escapeHtml(sub || '')}</div>
        </div>
    `;
}

function renderRemediationPlan(items) {
    const container = document.getElementById('remediation-plan');

    if (!items.length) {
        container.innerHTML = '<div class="v-empty">Нет данных</div>';
        return;
    }

    container.innerHTML = items.slice(0, 8).map((item, idx) => `
        <div class="v-remediation-card">
            <button class="v-remediation-main" data-remediation-index="${idx}">
                <div class="v-row-main">
                    <div class="v-row-name">
                        #${idx + 1} ${escapeHtml(item.product)}
                    </div>

                    <div class="v-row-meta">
                        ${item.cves_count} CVE ·
                        ${item.critical_now} active exploit ·
                        ${item.kev_count} KEV
                    </div>

                    <div class="v-row-meta">
                        ${escapeHtml(item.recommendation)}
                    </div>

                    <div class="v-remediation-impact">
                        Closes ${item.risk_reduction_percent.toFixed(1)}% of total vault risk
                    </div>
                </div>

                <span class="v-row-score">
                    ${item.remediation_score.toFixed(0)}
                </span>
            </button>

            <div class="v-remediation-details" style="display:none;">
                <div class="v-remediation-details-title">Top blocking CVEs</div>

                <div class="v-remediation-cves">
                    ${item.top_cves.map(cve => `
                        <button class="v-remediation-cve" data-path="${escapeHtml(cve.relative_path)}">
                            <span class="v-remediation-cve-id">${escapeHtml(cve.cve_id)}</span>
                            <span class="v-remediation-cve-meta">
                                ${escapeHtml(cve.risk_tier)} · risk ${cve.risk_score.toFixed(1)} · CVSS ${cve.cvss.toFixed(1)}
                            </span>
                        </button>
                    `).join('')}
                </div>
            </div>
        </div>
    `).join('');

    container.querySelectorAll('.v-remediation-main').forEach(button => {
        button.addEventListener('click', () => {
            const card = button.closest('.v-remediation-card');
            const details = card.querySelector('.v-remediation-details');

            const isOpen = details.style.display !== 'none';
            details.style.display = isOpen ? 'none' : 'block';
            card.classList.toggle('is-open', !isOpen);
        });
    });

    container.querySelectorAll('.v-remediation-cve').forEach(button => {
        button.addEventListener('click', () => {
            const path = button.dataset.path;
            if (!path) return;

            document.querySelector('.tab[data-tab="browse"]')?.click();
            openNote(path, null);
        });
    });
}

function renderRemediationSummary(summary, items) {
    const el = document.getElementById('remediation-summary');
    if (!el) return;

    const immediate = items.filter(i =>
        i.recommendation === 'Patch immediately'
    ).length;

    const kev = items.reduce((sum, i) => sum + i.kev_count, 0);

    el.innerHTML = `
        <span>${summary.products} products</span>
        <span>${summary.cves} CVE</span>
        <span>${kev} KEV</span>
        <span>${immediate} immediate</span>
    `;
}

function kpiCard(label, value, type, sub) {
    const subHtml = sub ? `<div class="kpi-sub">${escapeHtml(sub)}</div>` : '';
    return `
        <div class="kpi-card kpi-${type}">
            <div class="kpi-label">${escapeHtml(label)}</div>
            <div class="kpi-value">${value}</div>
            ${subHtml}
        </div>
    `;
}

function renderTierBars(distribution) {
    const container = document.getElementById('tier-bars');
    if (distribution.length === 0) {
        container.innerHTML = '<div class="v-empty">Нет данных</div>';
        return;
    }
    container.innerHTML = distribution.map(t => `
        <div class="v-tier-row">
            <span class="v-tier-label">${escapeHtml(t.label)}</span>
            <div class="v-tier-track">
                <div class="v-tier-fill v-tier-fill-${t.tier}" style="width: ${t.percent}%"></div>
            </div>
            <span class="v-tier-count">${t.count} (${t.percent}%)</span>
        </div>
    `).join('');
}

function renderTopCves(cves) {
    const container = document.getElementById('top-cves');
    if (cves.length === 0) {
        container.innerHTML = '<div class="v-empty">Нет данных</div>';
        return;
    }
    container.innerHTML = cves.map(c => {
        const risk = (c.risk_score !== null && c.risk_score !== undefined)
            ? c.risk_score.toFixed(1) : '—';

        const tierBadge = c.risk_tier
            ? `<span class="v-badge ${tierBadgeClass(c.risk_tier)}">${tierLabelShort(c.risk_tier)}</span>`
            : '';
        const kevBadge = c.kev ? '<span class="v-badge v-badge-critical">KEV</span>' : '';
        const ransomBadge = c.ransomware ? '<span class="v-badge v-badge-ransomware">RANSOM</span>' : '';

        return `
            <div class="v-row" data-path="${escapeHtml(c.relative_path)}">
                <div class="v-row-main">
                    <div class="v-row-name">${escapeHtml(c.cve_id)}</div>
                    <div class="v-row-meta">${tierBadge} ${kevBadge} ${ransomBadge}</div>
                </div>
                <span class="v-row-score">${risk}</span>
            </div>
        `;
    }).join('');
    bindTopItemClicks(container);
}

function tierBadgeClass(tier) {
    return {
        'critical_now': 'v-badge-critical',
        'critical_likely': 'v-badge-critical',
        'high': 'v-badge-high',
        'medium': 'v-badge-medium',
        'low': 'v-badge-low',
    }[tier] || 'v-badge-info';
}

function tierLabelShort(tier) {
    return {
        'critical_now': 'CRIT-NOW',
        'critical_likely': 'CRIT',
        'high': 'HIGH',
        'medium': 'MED',
        'low': 'LOW',
    }[tier] || tier.toUpperCase();
}

function renderTopProducts(products) {
    const container = document.getElementById('top-products');
    if (products.length === 0) {
        container.innerHTML = '<div class="v-empty">Нет данных</div>';
        return;
    }
    container.innerHTML = products.map(p => {
        const parts = [];
        if (p.critical_now) parts.push(`<span class="v-badge v-badge-critical">${p.critical_now} CRIT-NOW</span>`);
        if (p.critical_likely) parts.push(`<span class="v-badge v-badge-critical">${p.critical_likely} CRIT</span>`);
        if (p.high) parts.push(`<span class="v-badge v-badge-high">${p.high} HIGH</span>`);
        const meta = parts.length ? parts.join(' ') : `<span style="color:#8c909f;">всего ${p.total} CVE</span>`;

        return `
            <div class="v-row" data-path="products/${escapeHtml(p.name)}.md">
                <div class="v-row-main">
                    <div class="v-row-name">${escapeHtml(p.name)}</div>
                    <div class="v-row-meta">${meta}</div>
                </div>
                <span class="v-row-score">${p.total}</span>
            </div>
        `;
    }).join('');
    bindTopItemClicks(container);
}

function renderTopCwes(cwes) {
    const container = document.getElementById('top-cwes');
    if (cwes.length === 0) {
        container.innerHTML = '<div class="v-empty">Нет данных</div>';
        return;
    }
    container.innerHTML = cwes.map(c => {
        const critPart = c.critical_count
            ? `<span class="v-badge v-badge-critical">${c.critical_count} крит.</span>`
            : '';
        return `
            <div class="v-row" data-path="${escapeHtml(c.relative_path)}">
                <div class="v-row-main">
                    <div class="v-row-name">${escapeHtml(c.cwe_id)}</div>
                    <div class="v-row-meta">${c.count} CVE ${critPart}</div>
                </div>
                <span class="v-row-score">${c.count}</span>
            </div>
        `;
    }).join('');
    bindTopItemClicks(container);
}

function renderKevDeadlines(deadlines) {
    const container = document.getElementById('kev-deadlines');
    if (deadlines.length === 0) {
        container.innerHTML = '<div class="v-empty">Нет CISA-дедлайнов в ближайшие 30 дней</div>';
        return;
    }
    container.innerHTML = deadlines.map(d => {
        const cls = d.overdue ? 'v-deadline-overdue' : 'v-deadline-soon';
        const text = d.overdue
            ? `просрочено на ${Math.abs(d.days_remaining)} дн.`
            : `${d.days_remaining} дн. до дедлайна`;
        return `
            <div class="v-row" data-path="${escapeHtml(d.relative_path)}">
                <div class="v-row-main">
                    <div class="v-row-name">${escapeHtml(d.cve_id)}</div>
                    <div class="v-row-meta ${cls}">${escapeHtml(d.kev_due)} · ${escapeHtml(text)}</div>
                </div>
            </div>
        `;
    }).join('');
    bindTopItemClicks(container);
}

function renderRansomware(cves) {
    const section = document.getElementById('ransomware-section');
    const container = document.getElementById('ransomware-list');
    if (cves.length === 0) {
        section.style.display = 'none';
        return;
    }
    section.style.display = 'block';
    container.innerHTML = cves.map(c => {
        const tierBadge = c.risk_tier
            ? `<span class="v-badge ${tierBadgeClass(c.risk_tier)}">${tierLabelShort(c.risk_tier)}</span>`
            : '';
        return `
            <div class="v-row" data-path="${escapeHtml(c.relative_path)}">
                <div class="v-row-main">
                    <div class="v-row-name">${escapeHtml(c.cve_id)}</div>
                    <div class="v-row-meta"><span class="v-badge v-badge-ransomware">RANSOMWARE</span> ${tierBadge}</div>
                </div>
            </div>
        `;
    }).join('');
    bindTopItemClicks(container);
}

function bindTopItemClicks(container) {
    container.querySelectorAll('.top-item').forEach(el => {
        el.addEventListener('click', () => {
            const path = el.dataset.path;
            if (!path) return;
            // Переключаемся на вкладку Просмотр
            const browseTab = document.querySelector('.tab[data-tab="browse"]');
            if (browseTab) browseTab.click();
            openNote(path, null);
            // Подсветить в sidebar
            const noteName = path.split('/').pop().replace('.md', '');
            document.querySelectorAll('.note-group li').forEach(li => {
                if (li.textContent === noteName) {
                    li.classList.add('active');
                    li.scrollIntoView({ block: 'nearest' });
                }
            });
        });
    });
}

async function loadRemediationPlan() {
    const container = document.getElementById('remediation-plan');
    if (!container) return;

    const r = await window.pywebview.api.get_remediation_plan_for_path(
        AppState.currentVaultPath
    );

    if (!r.ok) {
        container.innerHTML =
            `<div class="v-empty">Ошибка remediation: ${escapeHtml(r.error)}</div>`;
        return;
    }

    renderRemediationSummary(r.summary, r.items);
    renderRemediationPlan(r.items);
}