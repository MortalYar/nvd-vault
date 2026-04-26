document.addEventListener('DOMContentLoaded', () => {
    setupTabs();
    setupScanTab();
    setupVaultTab();
    setupBrowseTab();
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

// ---------- Tab 2: сборка vault ----------

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

        const interval = setInterval(async () => {
            const p = await window.pywebview.api.get_build_progress();
            log.textContent = p.messages.join('\n');
            if (!p.running) {
                clearInterval(interval);
                buildBtn.disabled = false;
            }
        }, 500);
    });
}

// ---------- Tab 3: просмотр vault ----------

function setupBrowseTab() {
    const openBtn = document.getElementById('open-vault-btn');
    const meta = document.getElementById('vault-meta');
    const browser = document.getElementById('vault-browser');
    const filterInput = document.getElementById('filter-input');

    openBtn.addEventListener('click', async () => {
        const folder = await window.pywebview.api.select_vault_folder();
        if (!folder.ok) return;

        const r = await window.pywebview.api.open_vault(folder.path);
        if (!r.ok) {
            meta.textContent = 'Ошибка: ' + r.error;
            return;
        }

        meta.textContent = `${r.meta.vault_name} · ` +
            `${r.meta.products_count} продуктов, ${r.meta.cves_count} CVE`;
        browser.style.display = 'grid';

        await loadNotesList();
    });

    filterInput.addEventListener('input', () => {
        const q = filterInput.value.toLowerCase();
        document.querySelectorAll('.note-group li').forEach(li => {
            const visible = li.textContent.toLowerCase().includes(q);
            li.style.display = visible ? '' : 'none';
        });
    });
}

async function loadNotesList() {
    const r = await window.pywebview.api.list_vault_notes();
    if (!r.ok) {
        console.error(r.error);
        return;
    }

    fillList('list-products', r.notes.products);
    fillList('list-cves', r.notes.cves);
    fillList('list-cwes', r.notes.cwes);
}

function fillList(elementId, notes) {
    const ul = document.getElementById(elementId);
    ul.innerHTML = '';

    if (notes.length === 0) {
        ul.innerHTML = '<li style="color:#6c7086;font-style:italic;cursor:default;">пусто</li>';
        return;
    }

    for (const note of notes) {
        const li = document.createElement('li');
        li.textContent = note.name;

        // Цветовая индикация для CVE
        const sev = note.frontmatter?.severity;
        if (sev) li.classList.add('sev-' + sev);

        // Определяем тип папки по элементу-контейнеру
        const folder = elementId.replace('list-', '');
        const subfolder = folder === 'cves' ? 'cves'
                        : folder === 'products' ? 'products'
                        : 'cwes';
        const relativePath = `${subfolder}/${note.path}`;

        li.addEventListener('click', () => openNote(relativePath, li));
        ul.appendChild(li);
    }
}

async function openNote(relativePath, listItem) {
    const r = await window.pywebview.api.read_note(relativePath);
    if (!r.ok) {
        document.getElementById('note-content').innerHTML =
            `<p style="color:#f38ba8;">Ошибка: ${escapeHtml(r.error)}</p>`;
        return;
    }

    // Помечаем активный элемент
    document.querySelectorAll('.note-group li').forEach(li => li.classList.remove('active'));
    if (listItem) listItem.classList.add('active');

    // Вырезаем frontmatter перед рендером (он уже распарсен)
    const body = stripFrontmatter(r.content);

    // Обрабатываем wiki-links перед marked
    const processedBody = await processWikilinks(body);

    // Рендерим markdown
    const html = marked.parse(processedBody);
    document.getElementById('note-content').innerHTML = html;

    // Навешиваем обработчики на wiki-links
    document.querySelectorAll('.markdown-body .wikilink').forEach(el => {
        if (el.classList.contains('broken')) return;
        el.addEventListener('click', () => {
            const target = el.dataset.target;
            if (target) {
                openNote(target, null);
                // Также активируем в sidebar
                const allLis = document.querySelectorAll('.note-group li');
                for (const li of allLis) {
                    if (li.textContent === el.dataset.linkName) {
                        li.classList.add('active');
                        li.scrollIntoView({block: 'nearest'});
                        break;
                    }
                }
            }
        });
    });
}

function stripFrontmatter(content) {
    const match = content.match(/^---\n[\s\S]*?\n---\n/);
    return match ? content.slice(match[0].length) : content;
}

async function processWikilinks(body) {
    // Находим все [[wiki-link]] и подменяем на HTML-теги
    const matches = [...body.matchAll(/\[\[([^\]]+)\]\]/g)];
    if (matches.length === 0) return body;

    // Резолвим каждую ссылку через бэк
    const linkMap = new Map();
    for (const m of matches) {
        const linkName = m[1];
        if (linkMap.has(linkName)) continue;
        const r = await window.pywebview.api.resolve_wikilink(linkName);
        linkMap.set(linkName, r.found ? r.relative_path : null);
    }

    // Подменяем
    return body.replace(/\[\[([^\]]+)\]\]/g, (full, linkName) => {
        const target = linkMap.get(linkName);
        if (target) {
            return `<span class="wikilink" data-target="${target}" data-link-name="${linkName}">${linkName}</span>`;
        }
        return `<span class="wikilink broken" title="Заметка не найдена">${linkName}</span>`;
    });
}