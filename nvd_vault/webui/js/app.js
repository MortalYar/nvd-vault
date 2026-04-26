document.addEventListener('DOMContentLoaded', () => {
    setupTabs();
    setupScanTab();
    setupVaultTab();
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
            status.textContent = 'Заполни продукт и версию.';
            return;
        }

        btn.disabled = true;
        status.textContent = `Сканирую ${product} ${version}...`;
        results.innerHTML = '';

        try {
            const result = await window.pywebview.api.scan_product(
                product, version, vendor || null, null
            );

            if (!result.ok) {
                status.textContent = 'Ошибка: ' + result.error;
                return;
            }
            status.textContent =
                `Готово. Vendor: ${result.vendor}. Найдено ${result.matched_count} из ${result.total_in_db} CVE.`;
            renderCves(results, result.vulnerabilities);
        } catch (e) {
            status.textContent = 'Ошибка JS: ' + e.message;
        } finally {
            btn.disabled = false;
        }
    });
}

function renderCves(container, cves) {
    if (cves.length === 0) {
        container.innerHTML = '<p>Уязвимости, затрагивающие версию, не найдены.</p>';
        return;
    }
    container.innerHTML = cves.map(cve => {
        const sevClass = (cve.severity || '').toLowerCase();
        const score = cve.score !== null ? cve.score.toFixed(1) : '—';
        const kevBadge = cve.cisa_kev ? '<span class="kev-badge">KEV</span>' : '';
        return `
            <div class="cve-card ${sevClass}">
                <div class="cve-header">
                    <span class="cve-id">${cve.cve_id}${kevBadge}</span>
                    <span class="cve-meta">${cve.severity || 'N/A'} · CVSS ${score}</span>
                </div>
                <div class="cve-desc">${escapeHtml(cve.description)}...</div>
            </div>
        `;
    }).join('');
}

function escapeHtml(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
}

// ---------- Tab 2: сборка vault'а ----------

function setupVaultTab() {
    const pickInv = document.getElementById('pick-inventory');
    const pickVault = document.getElementById('pick-vault');
    const invInput = document.getElementById('inventory-path');
    const vaultInput = document.getElementById('vault-path');
    const buildBtn = document.getElementById('build-btn');
    const log = document.getElementById('build-log');

    pickInv.addEventListener('click', async () => {
        const r = await window.pywebview.api.select_inventory_file();
        if (r.ok) {
            invInput.value = r.path;
            updateBuildButton();
        }
    });

    pickVault.addEventListener('click', async () => {
        const r = await window.pywebview.api.select_vault_folder();
        if (r.ok) {
            vaultInput.value = r.path;
            updateBuildButton();
        }
    });

    function updateBuildButton() {
        buildBtn.disabled = !(invInput.value && vaultInput.value);
    }

    buildBtn.addEventListener('click', async () => {
        buildBtn.disabled = true;
        log.textContent = 'Запуск...\n';

        const r = await window.pywebview.api.build_vault(
            invInput.value, vaultInput.value, null
        );
        if (!r.ok) {
            log.textContent += 'Ошибка: ' + r.error;
            buildBtn.disabled = false;
            return;
        }

        // Поллим прогресс каждые 500мс
        const interval = setInterval(async () => {
            const p = await window.pywebview.api.get_build_progress();
            log.textContent = p.messages.join('\n');
            if (!p.running) {
                clearInterval(interval);
                buildBtn.disabled = false;

                // Автоматически открыть папку vault'а после сборки
                const lastMsg = p.messages[p.messages.length - 1] || '';
                if (lastMsg.startsWith('DONE::')) {
                    await window.pywebview.api.open_path_in_explorer(vaultInput.value);
                }
            }
        }, 500);
    });
}