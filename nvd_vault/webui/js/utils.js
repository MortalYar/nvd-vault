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