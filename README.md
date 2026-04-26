# NVD Vault

Desktop-приложение для аудита уязвимостей по open-source-инвентарю. Принимает список продуктов в формате `inventory.json`, обращается к [NVD (National Vulnerability Database)](https://nvd.nist.gov/), генерирует **vault** в формате связанных Markdown-заметок и предоставляет встроенный просмотрщик с навигацией по wiki-ссылкам.

![Python](https://img.shields.io/badge/python-3.13-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-windows-lightgrey)

## Возможности

- **Сборка vault** из inventory.json с автоматическим определением vendor через NVD CPE Dictionary
- **Точный матчинг версий** через CPE 2.3 с учётом диапазонов (`versionStartIncluding`, `versionEndExcluding` и т. д.)
- **Связанная структура заметок:** для каждой CVE — отдельный документ, связанный wiki-ссылками с продуктами и типами слабостей (CWE)
- **Встроенный просмотрщик** с тёмной темой, sidebar-навигацией, фильтром, цветовой индикацией severity
- **Кликабельные wiki-ссылки** `[[CVE-...]]`, `[[product]]`, `[[CWE-...]]` — навигация между заметками без выхода из приложения
- **Информация из CISA KEV** (Known Exploited Vulnerabilities) — отметка активно эксплуатируемых уязвимостей
- **Экспорт vault в ZIP-архив** для архивации или передачи

## Технологический стек

- **Backend:** Python 3.13, без сторонних UI-библиотек
- **UI:** PyWebView (нативный WebView2 на Windows) + HTML/CSS/JS без фреймворков
- **Markdown:** [marked.js](https://marked.js.org/) для рендеринга
- **HTTP:** requests для NVD API 2.0

## Установка

```powershell
git clone https://github.com/<username>/nvd-vault.git
cd nvd-vault

# Создаём виртуальное окружение (Python 3.13)
py -3.13 -m venv venv
.\venv\Scripts\Activate.ps1

# Зависимости
pip install -r requirements.txt
```

## Запуск

```powershell
python app.py
```

Откроется окно приложения с тремя вкладками.

## Использование

### Вкладка «Быстрое сканирование»

Точечная проверка одного продукта без сохранения. Введи имя, версию и (опционально) vendor — получишь список CVE, затрагивающих указанную версию.

### Вкладка «Сборка Vault»

Полноценный аудит инвентаря. Подготовь `inventory.json` (см. `examples/sample_inventory.json`):

```json
{
  "vault_name": "My ELK Stack",
  "products": [
    { "name": "kibana", "version": "8.19.9", "vendor": "elastic" },
    { "name": "logstash", "version": "8.19.5", "vendor": "elastic" }
  ]
}
```

Выбери `inventory.json` и папку для vault, нажми «Собрать Vault». Приложение опросит NVD по каждому продукту и создаст структуру: