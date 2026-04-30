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

// ---------- Tab 2: сборка vault ----------

// ---------- Tab 2: сборка vault + inventory editor ----------

let currentInventoryPath = null;
let buildInputPreviewOk = false;

function setupVaultTab() {
    setupInventoryEditor();
    setupBuildSection();
}

function setupInventoryEditor() {
    const newBtn = document.getElementById('inv-new-btn');
    const openBtn = document.getElementById('inv-open-btn');
    const saveBtn = document.getElementById('inv-save-btn');
    const saveAsBtn = document.getElementById('inv-save-as-btn');
    const addBtn = document.getElementById('inv-add-product');
    const vaultNameInput = document.getElementById('inv-vault-name');

    // Стартовое состояние — пустая таблица
    renderEmptyTable();

    newBtn.addEventListener('click', () => {
        if (!confirmDiscardChanges()) return;
        currentInventoryPath = null;
        vaultNameInput.value = '';
        document.getElementById('products-tbody').innerHTML = '';
        addProductRow();
        updatePathDisplay();
        setStatus('Новый inventory создан. Заполни и сохрани.');
        updateInventoryButtons();
    });

    openBtn.addEventListener('click', async () => {
        if (!confirmDiscardChanges()) return;

        const dlg = await window.pywebview.api.select_inventory_file();
        if (!dlg.ok) return;

        const r = await window.pywebview.api.read_inventory(dlg.path);
        if (!r.ok) {
            setStatus('Ошибка: ' + r.error, 'error');
            return;
        }

        currentInventoryPath = dlg.path;
        vaultNameInput.value = r.vault_name || '';
        const tbody = document.getElementById('products-tbody');
        tbody.innerHTML = '';
        if (r.products.length === 0) {
            renderEmptyTable();
        } else {
            r.products.forEach(p => addProductRow(p));
        }
        updatePathDisplay();
        setStatus(`Загружено: ${r.products.length} продуктов`, 'success');
        updateInventoryButtons();

        // Автоматически устанавливаем как inventory-path для сборки
        document.getElementById('inventory-path').value = dlg.path;
        const buildInputPath = document.getElementById('build-input-path');
        if (buildInputPath) buildInputPath.value = dlg.path;
        updateBuildButton();
    });

    saveBtn.addEventListener('click', async () => {
        if (!currentInventoryPath) return;
        await saveInventory(currentInventoryPath);
    });

    saveAsBtn.addEventListener('click', async () => {
        const defaultName = (vaultNameInput.value || 'inventory')
            .replace(/[^a-zA-Z0-9_-]/g, '_') + '.json';
        const dlg = await window.pywebview.api.save_inventory_dialog(defaultName);
        if (!dlg.ok) return;

        if (await saveInventory(dlg.path)) {
            currentInventoryPath = dlg.path;
            updatePathDisplay();
            updateInventoryButtons();
        }
    });

    addBtn.addEventListener('click', () => {
        // Если в таблице placeholder "пусто" — убираем его
        const tbody = document.getElementById('products-tbody');
        if (tbody.querySelector('.v-empty-row')) {
            tbody.innerHTML = '';
        }
        addProductRow();
        updateInventoryButtons();
    });
}

function renderEmptyTable() {
    const tbody = document.getElementById('products-tbody');
    tbody.innerHTML = `
        <tr class="v-empty-row">
            <td colspan="4">Inventory пуст. Нажми «Добавить продукт» чтобы начать.</td>
        </tr>
    `;
}

function addProductRow(data = {}) {
    const tbody = document.getElementById('products-tbody');
    const row = document.createElement('tr');
    row.innerHTML = `
        <td><input type="text" class="prod-name" value="${escapeAttr(data.name || '')}" placeholder="напр. kibana"></td>
        <td><input type="text" class="prod-version" value="${escapeAttr(data.version || '')}" placeholder="8.19.9"></td>
        <td>
            <div class="v-vendor-cell">
                <input type="text" class="prod-vendor" value="${escapeAttr(data.vendor || '')}" placeholder="опционально">
                <button class="v-btn-discover" type="button" title="Найти vendor через NVD">
                    <span class="material-symbols-outlined" style="font-size: 14px;">search</span>
                </button>
            </div>
        </td>
        <td class="v-row-actions">
            <button class="v-btn-icon" type="button" title="Удалить">
                <span class="material-symbols-outlined" style="font-size: 16px;">close</span>
            </button>
        </td>
    `;

    // Удаление
    row.querySelector('.v-btn-icon').addEventListener('click', () => {
        row.remove();
        const tb = document.getElementById('products-tbody');
        if (tb.children.length === 0) renderEmptyTable();
        updateInventoryButtons();
    });

    // Discover vendor
    row.querySelector('.v-btn-discover').addEventListener('click', async (evt) => {
        const btn = evt.currentTarget;
        const nameInput = row.querySelector('.prod-name');
        const vendorInput = row.querySelector('.prod-vendor');
        const product = nameInput.value.trim();

        if (!product) {
            setStatus('Сначала введи имя продукта', 'error');
            return;
        }

        btn.disabled = true;
        const originalHtml = btn.innerHTML;
        btn.innerHTML = '<span class="material-symbols-outlined" style="font-size: 14px;">progress_activity</span>';

        const r = await window.pywebview.api.discover_vendor(product);

        btn.disabled = false;
        btn.innerHTML = originalHtml;

        if (!r.ok) {
            setStatus('Ошибка: ' + r.error, 'error');
            return;
        }
        if (r.vendors.length === 0) {
            setStatus(`Vendor для '${product}' не найден`, 'error');
            return;
        }

        // Один вариант — подставляем сразу
        if (r.vendors.length === 1) {
            vendorInput.value = r.vendors[0];
            setStatus(`Vendor: ${r.vendors[0]}`, 'success');
            return;
        }

        // Несколько — открываем модалку
        showVendorPicker(product, r.vendors, (chosen) => {
            vendorInput.value = chosen;
            setStatus(`Vendor: ${chosen}`, 'success');
        });
    });

    // При вводе любого поля — обновляем состояние кнопок
    row.querySelectorAll('input').forEach(input => {
        input.addEventListener('input', updateInventoryButtons);
    });

    tbody.appendChild(row);
    return row;
}

function gatherProducts() {
    const products = [];
    document.querySelectorAll('#products-tbody tr').forEach(row => {
        if (row.classList.contains('v-empty-row')) return;
        const name = row.querySelector('.prod-name')?.value.trim();
        const version = row.querySelector('.prod-version')?.value.trim();
        const vendor = row.querySelector('.prod-vendor')?.value.trim();
        if (!name || !version) return; // пропускаем неполные строки
        const item = { name, version };
        if (vendor) item.vendor = vendor;
        products.push(item);
    });
    return products;
}

async function saveInventory(path) {
    const vaultName = document.getElementById('inv-vault-name').value.trim();
    const products = gatherProducts();

    if (products.length === 0) {
        setStatus('Нечего сохранять — нет ни одного валидного продукта', 'error');
        return false;
    }

    const r = await window.pywebview.api.write_inventory(path, vaultName, products);
    if (!r.ok) {
        setStatus('Ошибка сохранения: ' + r.error, 'error');
        return false;
    }

    setStatus(`Сохранено: ${products.length} продуктов в ${path}`, 'success');

    // Автоматически выставляем сохранённый файл как путь для сборки
    document.getElementById('inventory-path').value = path;

    const buildInputPath = document.getElementById('build-input-path');
    if (buildInputPath) {
        buildInputPath.value = path;
    }
    
    const inputFormat = document.getElementById('input-format');
    if (inputFormat) {
        inputFormat.value = 'inventory';
    }

    updateBuildButton();
    await updateBuildInputPreview();

    return true;
}

function updateInventoryButtons() {
    const products = gatherProducts();
    const hasProducts = products.length > 0;
    document.getElementById('inv-save-as-btn').disabled = !hasProducts;
    document.getElementById('inv-save-btn').disabled =
        !hasProducts || !currentInventoryPath;
}

function updatePathDisplay() {
    const display = document.getElementById('inv-current-path');
    display.textContent = currentInventoryPath
        ? `Файл: ${currentInventoryPath}` : '';
}

function setStatus(msg, kind = '') {
    const el = document.getElementById('inv-status');
    el.textContent = msg;
    el.className = 'v-inv-status'
        + (kind === 'success' ? ' v-status-success'
         : kind === 'error' ? ' v-status-error'
         : '');
    if (kind === 'success') {
        setTimeout(() => {
            if (el.textContent === msg) {
                el.textContent = '';
                el.className = 'v-inv-status';
            }
        }, 5000);
    }
}

function confirmDiscardChanges() {
    const products = gatherProducts();
    const hasName = document.getElementById('inv-vault-name').value.trim().length > 0;
    if (products.length === 0 && !hasName) return true;
    return confirm('Несохранённые изменения будут потеряны. Продолжить?');
}


// ---------- Build section (нижняя часть вкладки) ----------

function setupBuildSection() {
    const pickVault = document.getElementById('pick-vault');
    const pickBuildInput = document.getElementById('pick-build-input');
    const buildInputPath = document.getElementById('build-input-path');
    const vaultInput = document.getElementById('vault-path');
    const buildBtn = document.getElementById('build-btn');
    const log = document.getElementById('build-log');
    const inputFormatSelect = document.getElementById('input-format');

    inputFormatSelect.addEventListener('change', async () => {
        await updateBuildInputPreview();
    });

    pickBuildInput.addEventListener('click', async () => {
        const r = await window.pywebview.api.select_input_file();
        if (r.ok) {
            document.getElementById('inventory-path').value = r.path;
            buildInputPath.value = r.path;

            const inputFormat = document.getElementById('input-format');
            inputFormat.value = guessInputFormat(r.path);

            updateBuildButton();
            await updateBuildInputPreview();
        }
    });

    pickVault.addEventListener('click', async () => {
        const r = await window.pywebview.api.select_vault_folder();
        if (r.ok) {
            vaultInput.value = r.path;
            updateBuildButton();
            await updateBuildInputPreview();
        }
    });

    buildBtn.addEventListener('click', async () => {
        const inventoryPath = document.getElementById('inventory-path').value;
        const vaultPath = vaultInput.value;
        const inputFormat = document.getElementById('input-format').value;

        buildBtn.disabled = true;
        log.textContent = 'Запуск...\n';
        showBuildProgress('STARTING', 'Запускаю сборку vault', 10);

        const r = await window.pywebview.api.build_vault(
            inventoryPath, vaultPath, null, inputFormat
        );

        if (!r.ok) {
            log.textContent += 'Ошибка: ' + r.error;
            buildBtn.disabled = false;
            return;
        }

        const interval = setInterval(async () => {
            const p = await window.pywebview.api.get_build_progress();
            log.textContent = p.messages.join('\n');

            const progress = inferBuildProgress(p.messages, p.running);
            showBuildProgress(progress.status, progress.subtitle, progress.percent);

            if (!p.running) {
                clearInterval(interval);
                buildBtn.disabled = false;
            }
        }, 500);
    });
}

function updateBuildButton() {
    const inv = document.getElementById('inventory-path').value;
    const vault = document.getElementById('vault-path').value;

    document.getElementById('build-btn').disabled =
        !(inv && vault && buildInputPreviewOk);
}

async function updateBuildInputPreview() {
    const inputPath = document.getElementById('inventory-path').value;
    const inputFormat = document.getElementById('input-format').value;
    const preview = document.getElementById('build-input-preview');

    if (!inputPath) {
        buildInputPreviewOk = false;
        preview.style.display = 'none';
        preview.innerHTML = '';
        updateBuildButton();
        return;
    }

    const r = await window.pywebview.api.preview_build_input(inputPath, inputFormat);

    if (!r.ok) {
        buildInputPreviewOk = false;
        preview.style.display = 'block';
        preview.className = 'v-input-preview v-input-preview-error';
        preview.innerHTML = `
            <div class="v-input-preview-title">Input preview</div>
            <div class="v-input-preview-error-text">Ошибка: ${escapeHtml(r.error)}</div>
        `;
        updateBuildButton();
        return;
    }

    const productsHtml = r.products.map(p => {
        const vendor = p.vendor ? `<span class="v-input-preview-vendor">${escapeHtml(p.vendor)}</span>` : '';
        return `
            <li>
                <span>${escapeHtml(p.name)} ${escapeHtml(p.version)}</span>
                ${vendor}
            </li>
        `;
    }).join('');

    const more = r.products_count > r.products.length
        ? `<li class="v-input-preview-more">и ещё ${r.products_count - r.products.length}</li>`
        : '';

    preview.style.display = 'block';
    preview.className = 'v-input-preview';
    preview.innerHTML = `
        <div class="v-input-preview-header">
            <div>
                <div class="v-input-preview-title">Input preview</div>
                <div class="v-input-preview-subtitle">${escapeHtml(inputPath)}</div>
            </div>
            <span class="v-badge v-badge-info">${escapeHtml(inputFormat.toUpperCase())}</span>
        </div>

        <div class="v-input-preview-grid">
            <div>
                <div class="v-input-preview-label">Vault</div>
                <div class="v-input-preview-value">${escapeHtml(r.vault_name)}</div>
            </div>
            <div>
                <div class="v-input-preview-label">Products</div>
                <div class="v-input-preview-value">${r.products_count}</div>
            </div>
        </div>

        <ul class="v-input-preview-products">
            ${productsHtml}
            ${more}
        </ul>
    `;

    buildInputPreviewOk = true;
    updateBuildButton();
}

// ---------- Tab 3: просмотр vault ----------

function setupBrowseTab() {
    const openBtn = document.getElementById('open-vault-btn');
    const exportBtn = document.getElementById('export-btn');
    const meta = document.getElementById('vault-meta');
    const browser = document.getElementById('vault-browser');
    const filterInput = document.getElementById('filter-input');
    const searchBar = document.getElementById('search-bar');
    const searchInput = document.getElementById('search-input');
    const searchClear = document.getElementById('search-clear');
    const searchResults = document.getElementById('search-results');

    openBtn.addEventListener('click', async () => {
        const folder = await window.pywebview.api.select_vault_folder();
        if (!folder.ok) return;

        const r = await window.pywebview.api.open_vault(folder.path);
        if (!r.ok) {
            meta.textContent = 'Ошибка: ' + r.error;
            return;
        }

        const indexed = r.meta.indexed_notes !== undefined
            ? `, проиндексировано ${r.meta.indexed_notes}` : '';
        meta.textContent = `${r.meta.vault_name} · ` +
            `${r.meta.products_count} продуктов, ${r.meta.cves_count} CVE${indexed}`;

        browser.style.display = 'grid';
        searchBar.style.display = 'flex';
        exportBtn.disabled = false;

        await loadNotesList();
    });

    exportBtn.addEventListener('click', async () => {
        const vaultName = meta.textContent.split(' · ')[0] || 'vault';
        const safeName = vaultName.replace(/[^a-zA-Z0-9_-]/g, '_');
        const dateStr = new Date().toISOString().slice(0, 10);
        const defaultName = `${safeName}_${dateStr}.zip`;

        const dlg = await window.pywebview.api.select_export_zip_path(defaultName);
        if (!dlg.ok) return;

        exportBtn.disabled = true;
        exportBtn.textContent = 'Архивирую...';

        const r = await window.pywebview.api.export_vault_zip(dlg.path);

        exportBtn.textContent = 'Экспорт в ZIP';
        exportBtn.disabled = false;

        if (!r.ok) {
            alert('Ошибка экспорта: ' + r.error);
            return;
        }
        alert(
            `Готово!\n\n` +
            `Файлов: ${r.files_added}\n` +
            `Размер: ${r.size_mb} МБ\n` +
            `Путь: ${r.path}`
        );
    });

    filterInput.addEventListener('input', () => {
        const q = filterInput.value.toLowerCase();
        document.querySelectorAll('.note-group li').forEach(li => {
            const visible = li.textContent.toLowerCase().includes(q);
            li.style.display = visible ? '' : 'none';
        });
    });

    // Sort и filter для CVE
    const cveSort = document.getElementById('cve-sort');
    const cveFilterKev = document.getElementById('cve-filter-kev');
    const cveFilterCritical = document.getElementById('cve-filter-critical');
    const cveFilterRansom = document.getElementById('cve-filter-ransom');

    [cveSort, cveFilterKev, cveFilterCritical, cveFilterRansom].forEach(el => {
        el.addEventListener('change', () => {
            renderCveList();
            // Применяем также текстовый фильтр заново
            const q = filterInput.value.toLowerCase();
            if (q) {
                document.querySelectorAll('.note-group li').forEach(li => {
                    const visible = li.textContent.toLowerCase().includes(q);
                    li.style.display = visible ? '' : 'none';
                });
            }
        });
    });

    // ---- Поиск ----
    let searchTimeout = null;

    searchInput.addEventListener('input', () => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => doSearch(searchInput.value), 200);
    });

    searchClear.addEventListener('click', () => {
        searchInput.value = '';
        searchResults.innerHTML = '';
    });

    async function doSearch(query) {
        if (!query || query.trim().length < 2) {
            searchResults.innerHTML = '';
            return;
        }

        const r = await window.pywebview.api.search_vault(query);
        if (!r.ok) {
            searchResults.innerHTML =
                `<div class="search-no-results">Ошибка: ${escapeHtml(r.error)}</div>`;
            return;
        }

        renderSearchResults(r.results, query);
    }

    function renderSearchResults(results, query) {
        if (results.length === 0) {
            searchResults.innerHTML =
                `<div class="search-no-results">Ничего не найдено: "${escapeHtml(query)}"</div>`;
            return;
        }

        // Если первый результат -- ошибка от FTS
        if (results[0]?.error) {
            searchResults.innerHTML =
                `<div class="search-no-results">${escapeHtml(results[0].error)}</div>`;
            return;
        }

        searchResults.innerHTML = results.map(r => {
            const folder = r.folder === 'cves' ? 'CVE'
                         : r.folder === 'products' ? 'Продукт'
                         : 'CWE';
            // excerpt уже содержит <mark>...</mark> от FTS5 -- не экранируем целиком
            const excerpt = sanitizeExcerpt(r.excerpt || '');
            return `
                <div class="search-result" data-path="${escapeHtml(r.relative_path)}">
                    <div class="search-result-header">
                        <span class="search-result-title">${escapeHtml(r.title)}</span>
                        <span class="search-result-folder">${folder}</span>
                    </div>
                    <div class="search-result-excerpt">${excerpt}</div>
                </div>
            `;
        }).join('');

        searchResults.querySelectorAll('.search-result').forEach(el => {
            el.addEventListener('click', () => {
                const path = el.dataset.path;
                openNote(path, null);
                // Активируем в sidebar
                const noteName = path.split('/').pop().replace('.md', '');
                document.querySelectorAll('.note-group li').forEach(li => {
                    if (li.textContent === noteName) {
                        li.classList.add('active');
                        li.scrollIntoView({block: 'nearest'});
                    }
                });
            });
        });
    }

    function sanitizeExcerpt(html) {
        // Разрешаем только <mark>, всё остальное экранируем
        // Простой подход: сначала экранируем всё, потом возвращаем <mark>
        const escaped = html
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');
        return escaped
            .replace(/&lt;mark&gt;/g, '<mark>')
            .replace(/&lt;\/mark&gt;/g, '</mark>');
    }
}

// Глобальное хранилище CVE для пересортировки на лету
let allCvesCache = [];

async function loadNotesList() {
    const r = await window.pywebview.api.list_vault_notes();
    if (!r.ok) {
        console.error(r.error);
        return;
    }

    fillList('list-products', r.notes.products);
    allCvesCache = r.notes.cves;
    renderCveList();
    fillList('list-cwes', r.notes.cwes);
}

function renderCveList() {
    const sortMode = document.getElementById('cve-sort').value;
    const filterKev = document.getElementById('cve-filter-kev').checked;
    const filterCritical = document.getElementById('cve-filter-critical').checked;
    const filterRansom = document.getElementById('cve-filter-ransom').checked;

    // 1. Фильтрация
    let filtered = allCvesCache.filter(note => {
        const fm = note.frontmatter || {};
        if (filterKev && !toBool(fm.kev)) return false;
        if (filterCritical) {
            const tier = fm.risk_tier || '';
            if (tier !== 'critical_now' && tier !== 'critical_likely') return false;
        }
        if (filterRansom && !toBool(fm.ransomware)) return false;
        return true;
    });

    // 2. Сортировка
    filtered = sortCves(filtered, sortMode);

    // 3. Рендер
    fillList('list-cves', filtered);

    // 4. Счётчик
    const counter = document.getElementById('cve-counter');
    counter.textContent = filtered.length === allCvesCache.length
        ? `${filtered.length}`
        : `${filtered.length} из ${allCvesCache.length}`;
}

function sortCves(notes, mode) {
    const tierOrder = {
        'critical_now': 0, 'critical_likely': 1,
        'high': 2, 'medium': 3, 'low': 4, 'unknown': 5,
    };

    const arr = [...notes];

    switch (mode) {
        case 'risk':
            arr.sort((a, b) => {
                const ta = tierOrder[a.frontmatter?.risk_tier || 'unknown'] ?? 99;
                const tb = tierOrder[b.frontmatter?.risk_tier || 'unknown'] ?? 99;
                if (ta !== tb) return ta - tb;
                const ra = parseFloat(a.frontmatter?.risk_score || 0);
                const rb = parseFloat(b.frontmatter?.risk_score || 0);
                return rb - ra;
            });
            break;
        case 'cvss':
            arr.sort((a, b) => {
                const va = parseFloat(a.frontmatter?.cvss || 0);
                const vb = parseFloat(b.frontmatter?.cvss || 0);
                return vb - va;
            });
            break;
        case 'epss':
            arr.sort((a, b) => {
                const va = parseFloat(a.frontmatter?.epss || 0);
                const vb = parseFloat(b.frontmatter?.epss || 0);
                return vb - va;
            });
            break;
        case 'published':
            arr.sort((a, b) => {
                const va = a.frontmatter?.published || '';
                const vb = b.frontmatter?.published || '';
                return vb.localeCompare(va);
            });
            break;
        case 'name':
        default:
            arr.sort((a, b) => a.name.localeCompare(b.name));
    }

    return arr;
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

        // Цветовая индикация: приоритет risk_tier, fallback на severity
        const tier = note.frontmatter?.risk_tier;
        const sev = note.frontmatter?.severity;
        if (tier) {
            li.classList.add('tier-' + tier);
        } else if (sev) {
            li.classList.add('sev-' + sev);
        }

        // Иконка KEV/ransomware рядом с именем
        const isKev = String(note.frontmatter?.kev || '').toLowerCase() === 'true';
        const isRansom = String(note.frontmatter?.ransomware || '').toLowerCase() === 'true';
        if (isKev || isRansom) {
            const icons = document.createElement('span');
            icons.className = 'v-note-badges';
            if (isKev) icons.textContent += '⚠';
            if (isRansom) icons.textContent += '🔒';
            li.appendChild(icons);
        }

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

        const r = await window.pywebview.api.get_graph_data();
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