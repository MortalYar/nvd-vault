document.addEventListener('DOMContentLoaded', () => {
    setupTabs();
    setupScanTab();
    setupVaultTab();
    setupBrowseTab();
    setupGraphTab();
    setupDashboardTab();
});

// ---------- Табы ----------

function setupTabs() {
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => {
            const target = tab.dataset.tab;
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            document.getElementById('tab-' + target).classList.add('active');
        });
    });
}

// ---------- Tab 1: одиночное сканирование ----------

function setupScanTab() {
    const btn = document.getElementById('scan-btn');
    const status = document.getElementById('scan-status');
    const results = document.getElementById('scan-results');

    btn.addEventListener('click', async () => {
        const product = document.getElementById('product').value.trim();
        const version = document.getElementById('version').value.trim();
        const vendor = document.getElementById('vendor').value.trim();

        if (!product || !version) {
            setScanStatus(status, 'Заполни продукт и версию.', 'error');
            return;
        }

        btn.disabled = true;
        setScanStatus(status, `Сканирую ${product} ${version}...`);
        results.innerHTML = '';

        try {
            const result = await window.pywebview.api.scan_product(
                product, version, vendor || null, null
            );

            if (!result.ok) {
                setScanStatus(status, 'Ошибка: ' + result.error, 'error');
                return;
            }
            setScanStatus(
                status,
                `Готово. Vendor: ${result.vendor} · найдено ${result.matched_count} из ${result.total_in_db} CVE.`,
                'success'
            );
            renderCves(results, result.vulnerabilities);
        } catch (e) {
            setScanStatus(status, 'Ошибка JS: ' + e.message, 'error');
        } finally {
            btn.disabled = false;
        }
    });
}

function setScanStatus(el, text, kind) {
    el.textContent = text;
    el.style.display = 'block';
    el.className = 'v-scan-status'
        + (kind === 'error' ? ' v-status-error'
         : kind === 'success' ? ' v-status-success'
         : '');
}

function renderCves(container, cves) {
    if (cves.length === 0) {
        container.innerHTML = '<div class="v-empty">Уязвимости, затрагивающие версию, не найдены.</div>';
        return;
    }
    container.innerHTML = cves.map(cve => {
        const tier = cve.risk_tier || 'unknown';
        const tierLabel = {
            'critical_now': 'КРИТИЧНО (эксплуатируется)',
            'critical_likely': 'КРИТИЧНО (вероятная эксплуатация)',
            'high': 'Высокий',
            'medium': 'Средний',
            'low': 'Низкий',
        }[tier] || 'Не определён';

        const cvssScore = (cve.score !== null && cve.score !== undefined)
            ? cve.score.toFixed(1) : '—';
        const riskScore = (cve.risk_score !== null && cve.risk_score !== undefined)
            ? cve.risk_score.toFixed(1) : '—';

        const badges = [];
        if (cve.cisa_kev) badges.push('<span class="v-badge v-badge-critical">KEV</span>');
        if (cve.kev_known_ransomware) badges.push('<span class="v-badge v-badge-ransomware">RANSOMWARE</span>');
        if (cve.epss_score !== null && cve.epss_score !== undefined) {
            badges.push(`<span class="v-badge v-badge-info">EPSS ${cve.epss_score.toFixed(2)}</span>`);
        }
        if (tier !== 'unknown') {
            badges.push(`<span class="v-badge ${tierBadgeClass(tier)}">${tierLabelShort(tier)}</span>`);
        }

        return `
            <div class="v-cve-card v-tier-${tier}">
                <div class="v-cve-header">
                    <span class="v-cve-id">${escapeHtml(cve.cve_id)}</span>
                    <span class="v-cve-meta">Risk ${riskScore}/10 · CVSS ${cvssScore}</span>
                </div>
                <div class="v-cve-tier-line">
                    <span>${escapeHtml(tierLabel)}</span>
                    <span class="v-cve-badges">${badges.join('')}</span>
                </div>
                <div class="v-cve-desc">${escapeHtml(cve.description)}...</div>
            </div>
        `;
    }).join('');
}
// ---------- Tab 4: граф ----------

let graphInstance = null;
let graphRawData = null;

function setupGraphTab() {
    const loadBtn = document.getElementById('graph-load-btn');
    const stats = document.getElementById('graph-stats');
    const controls = document.getElementById('graph-controls');
    const fitBtn = document.getElementById('graph-fit');
    const relayoutBtn = document.getElementById('graph-relayout');

    loadBtn.addEventListener('click', async () => {
        loadBtn.disabled = true;
        loadBtn.textContent = 'Загружаю...';

        if (!AppState.hasVault()) {
            stats.textContent = 'Сначала открой vault во вкладке «Просмотр Vault».';
            loadBtn.disabled = false;
            loadBtn.textContent = 'Построить';
            return;
        }

        const r = await window.pywebview.api.get_graph_data_for_path(AppState.currentVaultPath);

        loadBtn.disabled = false;
        loadBtn.textContent = 'Перестроить граф';

        if (!r.ok) {
            stats.textContent = 'Ошибка: ' + r.error;
            return;
        }

        graphRawData = r;
        stats.textContent =
            `${r.stats.products} ${plural(r.stats.products, 'продукт', 'продукта', 'продуктов')} · ` +
            `${r.stats.cves} CVE · ` +
            `${r.stats.cwes} CWE · ` +
            `${r.stats.edges} ${plural(r.stats.edges, 'связь', 'связи', 'связей')}`;

        controls.style.display = 'flex';
        renderGraph(r.nodes, r.edges);
    });

    fitBtn.addEventListener('click', () => {
        if (graphInstance) graphInstance.fit(undefined, 50);
    });

    relayoutBtn.addEventListener('click', () => {
        if (graphInstance) runLayout(graphInstance);
    });

    const exportPngBtn = document.getElementById('graph-export-png');
    exportPngBtn.addEventListener('click', async () => {
        if (!graphInstance) return;

        const dateStr = new Date().toISOString().slice(0, 10);
        const defaultName = `vault-graph_${dateStr}.png`;

        const dlg = await window.pywebview.api.select_export_png_path(defaultName);
        if (!dlg.ok) return;

        exportPngBtn.disabled = true;
        exportPngBtn.textContent = 'Сохраняю...';

        // Снимаем подсветку перед экспортом — иначе она попадёт на картинку
        clearHighlight(graphInstance);

        // cy.png() возвращает data URI
        // Параметры: bg — фон, scale — кратность размера для retina-качества
        const dataUri = graphInstance.png({
            bg: '#1e1e2e',
            scale: 2,
            full: true,        // экспортируем весь граф, не только видимое
        });

        const r = await window.pywebview.api.save_graph_png(dlg.path, dataUri);

        exportPngBtn.disabled = false;
        exportPngBtn.textContent = 'Экспорт PNG';

        if (!r.ok) {
            alert('Ошибка: ' + r.error);
            return;
        }
        alert(`Готово!\n\nФайл: ${r.path}\nРазмер: ${r.size_kb} КБ`);
    });

    // Фильтры
    ['filter-critical', 'filter-high', 'filter-medium', 'filter-low',
     'filter-unknown', 'filter-kev-only', 'filter-hide-cwe'].forEach(id => {
        document.getElementById(id).addEventListener('change', applyGraphFilters);
    });
}

function renderGraph(nodes, edges) {
    const container = document.getElementById('graph-container');
    container.innerHTML = '';

    if (graphInstance) {
        graphInstance.destroy();
        graphInstance = null;
    }

    graphInstance = cytoscape({
        container: container,
        elements: { nodes, edges },
        style: getCytoscapeStyle(),
    });

    runLayout(graphInstance);
    setupGraphInteractions(graphInstance);
    applyGraphFilters();
}

function getCytoscapeStyle() {
    return [
        // Базовый стиль узлов
        {
            selector: 'node',
            style: {
                'label': 'data(label)',
                'color': '#d3e4fe',
                'font-family': 'Inter, sans-serif',
                'font-size': '10px',
                'text-outline-color': '#031427',
                'text-outline-width': 2,
                'text-valign': 'center',
                'text-halign': 'center',
                'border-width': 0,
            },
        },
        // Продукты — синие плашки в стиле Vault Sentinel
        {
            selector: 'node[type="product"]',
            style: {
                'shape': 'round-rectangle',
                'background-color': '#4d8eff',
                'width': 84,
                'height': 32,
                'color': '#ffffff',
                'font-weight': 'bold',
                'text-outline-width': 0,
                'border-width': 1,
                'border-color': '#adc6ff',
            },
        },
        // CWE — серые ромбы
        {
            selector: 'node[type="cwe"]',
            style: {
                'shape': 'diamond',
                'background-color': '#26364a',
                'width': 40,
                'height': 40,
                'border-width': 1,
                'border-color': '#424754',
            },
        },
        // CVE — круги по severity
        {
            selector: 'node[type="cve"]',
            style: {
                'shape': 'ellipse',
                'width': 24,
                'height': 24,
                'background-color': '#8c909f',
                'border-width': 1,
                'border-color': '#26364a',
            },
        },
        { selector: 'node[severity="critical"]', style: { 'background-color': '#ffb4ab', 'border-color': '#93000a' } },
        { selector: 'node[severity="high"]',     style: { 'background-color': '#ffb786', 'border-color': '#df7412' } },
        { selector: 'node[severity="medium"]',   style: { 'background-color': '#f9e2af', 'border-color': '#a08000' } },
        { selector: 'node[severity="low"]',      style: { 'background-color': '#a6e3a1', 'border-color': '#3a8035' } },
        // KEV — обводка ярче и толще
        {
            selector: 'node[type="cve"][?kev]',
            style: {
                'border-width': 3,
                'border-color': '#ffb4ab',
            },
        },
        // Рёбра
        {
            selector: 'edge',
            style: {
                'width': 1,
                'line-color': '#26364a',
                'curve-style': 'bezier',
                'target-arrow-shape': 'none',
                'opacity': 0.7,
            },
        },
        {
            selector: 'edge[type="instance-of"]',
            style: {
                'line-color': '#424754',
                'line-style': 'dashed',
            },
        },
        // Подсветка / затемнение
        {
            selector: '.dimmed',
            style: {
                'opacity': 0.12,
                'text-opacity': 0.12,
            },
        },
        {
            selector: '.highlighted',
            style: {
                'border-width': 3,
                'border-color': '#adc6ff',
                'z-index': 10,
            },
        },
        {
            selector: 'edge.highlighted',
            style: {
                'width': 2.5,
                'line-color': '#4d8eff',
                'opacity': 1,
                'z-index': 10,
            },
        },
        {
            selector: 'node.focused',
            style: {
                'border-width': 4,
                'border-color': '#ffb786',
                'z-index': 20,
            },
        },
    ];
}

function runLayout(cy) {
    const layoutName = (typeof cytoscape.use !== 'undefined') ? 'cose-bilkent' : 'cose';
    try {
        cy.layout({
            name: 'cose-bilkent',
            animate: false,
            randomize: true,
            nodeRepulsion: 8000,
            idealEdgeLength: 80,
            edgeElasticity: 0.45,
            gravity: 0.25,
            numIter: 2500,
            tile: true,
        }).run();
    } catch (e) {
        // Fallback если плагин не подгрузился
        cy.layout({ name: 'cose', animate: false }).run();
    }
    cy.fit(undefined, 50);
}

function setupGraphInteractions(cy) {
    const tooltip = document.getElementById('graph-tooltip');

    // Hover — tooltip
    cy.on('mouseover', 'node', (evt) => {
        const node = evt.target;
        const d = node.data();
        let html = `<strong>${escapeHtml(d.label)}</strong><br>тип: ${d.type}`;
        if (d.type === 'cve') {
            html += `<br>severity: ${d.severity || '—'}`;
            if (d.cvss !== null && d.cvss !== undefined) html += ` · CVSS ${d.cvss}`;
            if (d.kev) html += '<br><strong style="color:#f38ba8">CISA KEV</strong>';
        } else if (d.type === 'product') {
            if (d.vendor) html += `<br>vendor: ${d.vendor}`;
            if (d.version) html += `<br>версия: ${d.version}`;
            if (d.cve_count) html += `<br>CVE: ${d.cve_count}`;
        } else if (d.type === 'cwe') {
            if (d.cve_count) html += `<br>CVE этого типа: ${d.cve_count}`;
        }
        tooltip.innerHTML = html;
        tooltip.style.display = 'block';
    });

    cy.on('mouseout', 'node', () => {
        tooltip.style.display = 'none';
    });

    cy.on('mousemove', (evt) => {
        if (tooltip.style.display === 'none') return;
        const e = evt.originalEvent;
        tooltip.style.left = (e.clientX + 14) + 'px';
        tooltip.style.top = (e.clientY + 14) + 'px';
    });

    // Одиночный клик — highlight соседей
    cy.on('tap', 'node', (evt) => {
        const node = evt.target;
        highlightNeighborhood(cy, node);
    });

    // Двойной клик — переход к заметке
    cy.on('dbltap', 'node', async (evt) => {
        const d = evt.target.data();
        if (!d.relative_path) return;
        const browseTab = document.querySelector('.tab[data-tab="browse"]');
        if (browseTab) browseTab.click();
        await openNote(d.relative_path, null);
        const noteName = d.relative_path.split('/').pop().replace('.md', '');
        document.querySelectorAll('.note-group li').forEach(li => {
            if (li.textContent === noteName) {
                li.classList.add('active');
                li.scrollIntoView({block: 'nearest'});
            }
        });
    });

    // Клик по пустому месту — снять подсветку
    cy.on('tap', (evt) => {
        if (evt.target === cy) {
            clearHighlight(cy);
        }
    });
}

function applyGraphFilters() {
    if (!graphInstance) return;

    const showCritical = document.getElementById('filter-critical').checked;
    const showHigh = document.getElementById('filter-high').checked;
    const showMedium = document.getElementById('filter-medium').checked;
    const showLow = document.getElementById('filter-low').checked;
    const showUnknown = document.getElementById('filter-unknown').checked;
    const kevOnly = document.getElementById('filter-kev-only').checked;
    const hideCwe = document.getElementById('filter-hide-cwe').checked;

    graphInstance.batch(() => {
        graphInstance.elements().forEach(el => {
            const d = el.data();
            let visible = true;

            if (el.isNode()) {
                if (d.type === 'cwe' && hideCwe) visible = false;
                if (d.type === 'cve') {
                    const sev = d.severity || 'unknown';
                    if (sev === 'critical' && !showCritical) visible = false;
                    if (sev === 'high' && !showHigh) visible = false;
                    if (sev === 'medium' && !showMedium) visible = false;
                    if (sev === 'low' && !showLow) visible = false;
                    if (!['critical','high','medium','low'].includes(sev) && !showUnknown) visible = false;
                    if (kevOnly && !d.kev) visible = false;
                }
            }
            el.style('display', visible ? 'element' : 'none');
        });
    });
    // Сбрасываем highlight при изменении фильтров
    clearHighlight(graphInstance);
}

function highlightNeighborhood(cy, node) {
    // Снимаем предыдущую подсветку
    cy.elements().removeClass('highlighted focused dimmed');

    // Соседи: связанные узлы + рёбра между ними
    const neighborhood = node.closedNeighborhood();

    // Затемняем всё остальное
    cy.elements().not(neighborhood).addClass('dimmed');

    // Подсвечиваем соседей
    neighborhood.addClass('highlighted');

    // Целевой узел отмечаем особо
    node.removeClass('highlighted');
    node.addClass('focused');
}

function clearHighlight(cy) {
    cy.elements().removeClass('highlighted focused dimmed');
}

/**
 * Показать модалку выбора vendor.
 * vendors -- список вариантов от NVD, отсортированных по релевантности.
 * onPick -- callback с выбранным значением.
 */
function showVendorPicker(product, vendors, onPick) {
    const modal = document.getElementById('vendor-modal');
    const subtitle = document.getElementById('vendor-modal-subtitle');
    const list = document.getElementById('vendor-modal-list');
    const closeBtn = document.getElementById('vendor-modal-close');

    subtitle.textContent =
        `NVD предложил ${vendors.length} ${plural(vendors.length, 'вариант', 'варианта', 'вариантов')} ` +
        `для продукта '${product}'. Выбери подходящий.`;

    list.innerHTML = vendors.map((v, idx) => `
        <button class="v-modal-vendor" data-vendor="${escapeAttr(v)}">
            <span>${escapeHtml(v)}</span>
            <span class="v-modal-vendor-rank">${idx === 0 ? 'наиболее частый' : '#' + (idx + 1)}</span>
        </button>
    `).join('');

    function close() {
        modal.style.display = 'none';
        list.querySelectorAll('.v-modal-vendor').forEach(b => b.replaceWith(b.cloneNode(true)));
        closeBtn.removeEventListener('click', close);
        modal.removeEventListener('click', onOverlayClick);
        document.removeEventListener('keydown', onEsc);
    }

    function onOverlayClick(evt) {
        if (evt.target === modal) close();
    }

    function onEsc(evt) {
        if (evt.key === 'Escape') close();
    }

    list.querySelectorAll('.v-modal-vendor').forEach(btn => {
        btn.addEventListener('click', () => {
            const chosen = btn.dataset.vendor;
            close();
            onPick(chosen);
        });
    });

    closeBtn.addEventListener('click', close);
    modal.addEventListener('click', onOverlayClick);
    document.addEventListener('keydown', onEsc);

    modal.style.display = 'flex';
}