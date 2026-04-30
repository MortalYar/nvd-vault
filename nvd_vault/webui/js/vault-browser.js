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