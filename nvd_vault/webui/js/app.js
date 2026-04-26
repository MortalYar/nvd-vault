document.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('scan-btn');
    const status = document.getElementById('status');
    const results = document.getElementById('results');

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
                status.textContent = `Ошибка: ${result.error}`;
                return;
            }

            status.textContent =
                `Готово. Vendor: ${result.vendor}. ` +
                `Найдено ${result.matched_count} из ${result.total_in_db} CVE.`;

            renderCves(result.vulnerabilities);
        } catch (e) {
            status.textContent = 'Ошибка JS: ' + e.message;
        } finally {
            btn.disabled = false;
        }
    });
});

function renderCves(cves) {
    const container = document.getElementById('results');

    if (cves.length === 0) {
        container.innerHTML = '<p>Уязвимости, затрагивающие версию, не найдены.</p>';
        return;
    }

    container.innerHTML = cves.map(cve => {
        const sevClass = (cve.severity || '').toLowerCase();
        const score = cve.score !== null ? cve.score.toFixed(1) : '—';
        const kevBadge = cve.cisa_kev
            ? '<span class="kev-badge">KEV</span>' : '';

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
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}