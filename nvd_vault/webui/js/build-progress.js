function showBuildProgress(status, subtitle, percent) {
    const card = document.getElementById('build-progress-card');
    const badge = document.getElementById('build-progress-badge');
    const subtitleEl = document.getElementById('build-progress-subtitle');
    const bar = document.getElementById('build-progress-bar');

    if (!card || !badge || !subtitleEl || !bar) return;

    card.style.display = 'block';
    badge.textContent = status;
    subtitleEl.textContent = subtitle;
    bar.style.width = `${percent}%`;
}

function inferBuildProgress(messages, running) {
    const text = messages.join('\n');

    if (!running && text.includes('DONE::')) {
        return { status: 'DONE', subtitle: 'Vault успешно собран', percent: 100 };
    }

    if (text.includes('ERROR::')) {
        return { status: 'ERROR', subtitle: 'Сборка завершилась с ошибкой', percent: 100 };
    }

    if (text.includes('Генерирую vault')) {
        return { status: 'GENERATING', subtitle: 'Генерирую Markdown vault', percent: 85 };
    }

    if (text.includes('Обогащаю')) {
        return { status: 'ENRICHING', subtitle: 'Загружаю EPSS и CISA KEV', percent: 65 };
    }

    if (text.includes('Сканирую')) {
        return { status: 'SCANNING', subtitle: 'Сканирую продукты через NVD', percent: 35 };
    }

    return {
        status: running ? 'RUNNING' : 'READY',
        subtitle: running ? 'Сборка запущена' : 'Ожидание запуска',
        percent: running ? 10 : 0,
    };
}