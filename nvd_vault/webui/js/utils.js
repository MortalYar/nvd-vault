function escapeHtml(str) {
    const d = document.createElement('div');
    d.textContent = str ?? '';
    return d.innerHTML;
}

function escapeAttr(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

function toBool(value) {
    if (typeof value === 'boolean') return value;
    return String(value).toLowerCase() === 'true';
}

function plural(n, one, few, many) {
    const mod10 = n % 10;
    const mod100 = n % 100;

    if (mod10 === 1 && mod100 !== 11) return one;
    if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return few;

    return many;
}

function guessInputFormat(path) {
    const lower = String(path || '').toLowerCase();

    if (
        lower.includes('sbom') ||
        lower.includes('cyclonedx') ||
        lower.includes('spdx')
    ) {
        return 'sbom';
    }

    if (lower.includes('inventory')) {
        return 'inventory';
    }

    return 'auto';
}

function safeFilename(value, fallback = 'untitled') {
    // Имя файла, безопасное для всех современных ФС.
    // Сохраняем unicode, цифры, дефис, подчёркивание, точку.
    // Заменяем пробелы на _ и режем зарезервированные символы Windows.
    let name = String(value ?? '').trim();
    if (!name) return fallback;

    // Зарезервированные на Windows: < > : " / \ | ? * + управляющие 0x00-0x1F
    name = name.replace(/[<>:"/\\|?*\x00-\x1F]/g, '_');

    // Пробелы и табы → _
    name = name.replace(/\s+/g, '_');

    // Точки в начале/конце Windows не любит ("Untitled." и ".file" глюкавят)
    name = name.replace(/^\.+|\.+$/g, '');

    // Длина: безопасный предел — 200 символов (NTFS лимит 255 на компонент пути,
    // оставляем запас под расширение и timestamp).
    if (name.length > 200) name = name.slice(0, 200);

    return name || fallback;
}