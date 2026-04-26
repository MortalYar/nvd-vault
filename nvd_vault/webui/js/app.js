// Главный entry point фронтенда

document.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('ping-btn');
    const result = document.getElementById('result');

    btn.addEventListener('click', async () => {
        try {
            const response = await window.pywebview.api.ping();
            result.textContent = response;
        } catch (e) {
            result.textContent = 'Ошибка: ' + e.message;
        }
    });
});