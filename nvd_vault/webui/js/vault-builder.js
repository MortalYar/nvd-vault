//------------------ Tab 2: сборка vault ---------------

// ---------- сборка vault + inventory editor ----------

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