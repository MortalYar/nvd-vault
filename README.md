# NVD Vault

Desktop-приложение для аудита уязвимостей по open-source-инвентарю с приоритизацией патчинга. Принимает список продуктов в формате `inventory.json`, обращается к [NVD](https://nvd.nist.gov/), [EPSS](https://www.first.org/epss/) и [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), генерирует **vault** в формате связанных Markdown-заметок и предоставляет встроенный просмотрщик с поиском, графом связей и дашбордом.

![Python](https://img.shields.io/badge/python-3.13-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-windows-lightgrey)

## Возможности

- **Сборка vault** из inventory.json с автоматическим определением vendor через NVD CPE Dictionary
- **Точный матчинг версий** через CPE 2.3 с учётом диапазонов (`versionStartIncluding`, `versionEndExcluding` и т. д.)
- **Связанная структура заметок:** для каждой CVE — отдельный документ, связанный wiki-ссылками с продуктами и типами слабостей (CWE)
- **Приоритизация уязвимостей** на основе CVSS + EPSS + CISA KEV — пять risk tier'ов от `critical_now` (уже эксплуатируется) до `low`
- **Обогащение через EPSS** — вероятность активной эксплуатации в ближайшие 30 дней
- **Обогащение через CISA KEV** — каталог уязвимостей в активных атаках, метки ransomware-кампаний, CISA-дедлайны патчинга
- **Дашборд** с KPI, топом самых опасных CVE, топом продуктов по риску, списком CISA-дедлайнов
- **Полнотекстовый поиск** по содержимому vault через SQLite FTS5 с подсветкой совпадений
- **Интерактивный граф связей** CVE ↔ продукты ↔ CWE через cytoscape.js с фильтрами по severity и KEV-статусу
- **Встроенный просмотрщик** с тёмной темой, sidebar-навигацией, цветовой индикацией severity
- **Кликабельные wiki-ссылки** `[[CVE-...]]`, `[[product]]`, `[[CWE-...]]` — навигация между заметками без выхода из приложения
- **Экспорт vault в ZIP-архив** для архивации или передачи

## Технологический стек

- **Backend:** Python 3.13 (NVD API 2.0, EPSS API, CISA KEV feed)
- **UI:** PyWebView (нативный WebView2 на Windows) + HTML/CSS/JS без фреймворков
- **Markdown:** [marked.js](https://marked.js.org/) для рендеринга
- **Граф:** [cytoscape.js](https://js.cytoscape.org/) с layout cose-bilkent
- **Поиск:** SQLite FTS5 (in-memory, перестраивается при открытии vault)
- **HTTP:** requests с User-Agent и rate-limiting

## Установка

Приложение требует Python 3.13 (на 3.14 не работает из-за `pythonnet`).

### Windows

```powershell
git clone https://github.com/MortalYar/nvd-vault.git
cd nvd-vault

# Виртуальное окружение на Python 3.13
py -3.13 -m venv venv
.\venv\Scripts\Activate.ps1

# Зависимости
pip install -r requirements.txt
```

WebView2 (движок отрисовки) на Windows 11 уже встроен. На Windows 10 нужно установить отдельно: [WebView2 Runtime](https://developer.microsoft.com/en-us/microsoft-edge/webview2/).

### Linux (Ubuntu / Debian)

PyWebView под Linux использует GTK + WebKit. Нужно установить системные пакеты:

```bash
# Ubuntu 24.04 / Debian 12
sudo apt update
sudo apt install python3.13 python3.13-venv \
    python3-gi gir1.2-webkit2-4.1 \
    libgirepository1.0-dev

git clone https://github.com/MortalYar/nvd-vault.git
cd nvd-vault

python3.13 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
pip install pywebview[gtk]
```

Для других дистрибутивов:
- **Fedora / RHEL:** `sudo dnf install python3.13 webkit2gtk4.1 gobject-introspection-devel`
- **Arch:** `sudo pacman -S python webkit2gtk-4.1 gobject-introspection`

### macOS

PyWebView под macOS использует встроенный WKWebView, дополнительных пакетов не нужно:

```bash
git clone https://github.com/MortalYar/nvd-vault.git
cd nvd-vault

python3.13 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

> Сборка тестировалась только на Windows. Linux и macOS поддерживаются на уровне зависимостей PyWebView, но реальный UX может потребовать доработки.

## Запуск

```powershell
python app.py
```

Откроется окно приложения с пятью вкладками.

## Использование

### Вкладка «Дашборд»

Открывается автоматически после загрузки vault. Показывает:
- KPI: общее число CVE, активно эксплуатируемые (CISA KEV), вероятная эксплуатация (EPSS ≥ 0.7), ransomware-related, просроченные CISA-дедлайны
- Распределение CVE по risk tier (горизонтальный bar chart)
- Топ-10 самых опасных уязвимостей с risk score
- Топ-5 продуктов по числу критичных CVE
- Список CVE с CISA-дедлайнами в ближайшие 30 дней (включая просроченные)
- Топ типов слабостей (CWE)
- Отдельная секция уязвимостей в ransomware-кампаниях

Любой элемент кликабелен — открывает соответствующую заметку.

### Вкладка «Быстрое сканирование»

Точечная проверка одного продукта без сохранения. Введи имя, версию и (опционально) vendor — приложение опросит NVD, EPSS и KEV, посчитает risk tier и покажет результат, отсортированный по приоритету. Каждая карточка содержит CVSS, EPSS, метку KEV и ransomware-флаг.

### Вкладка «Сборка Vault»

Полноценный аудит инвентаря с сохранением результата на диск. Подготовь `inventory.json` (см. `examples/sample_inventory.json`):

```json
{
  "vault_name": "My ELK Stack",
  "products": [
    { "name": "kibana", "version": "8.19.9", "vendor": "elastic" },
    { "name": "logstash", "version": "8.19.5", "vendor": "elastic" }
  ]
}
```

Выбери файл inventory и папку для vault, нажми «Собрать Vault». Приложение опросит NVD по каждому продукту, обогатит результаты EPSS и CISA KEV, посчитает risk tier и создаст структуру связанных Markdown-заметок:

```
my-vault/
├── meta.json
├── cves/
│   ├── CVE-2025-37731.md
│   └── ...
├── products/
│   ├── kibana.md
│   └── logstash.md
└── cwes/
    ├── CWE-287.md
    └── ...
```

Каждая CVE-заметка содержит YAML frontmatter с метаданными (severity, CVSS, EPSS, KEV-статус, risk_tier, теги) и тело с приоритетом, обоснованием risk tier, описанием, CVSS-вектором, ссылками на патчи и wiki-ссылками `[[product]]` и `[[CWE-...]]` на связанные документы.

### Вкладка «Просмотр Vault»

Открой ранее собранный vault и листай его прямо в окне приложения. Возможности:

- **Sidebar-навигация** по продуктам, CVE и CWE с цветовой индикацией severity
- **Фильтр по имени** в боковой панели — мгновенное сужение списка
- **Полнотекстовый поиск** по содержимому всех заметок с подсветкой совпадений
- **Кликабельные wiki-ссылки** в теле заметок — переход между связанными документами
- **Экспорт vault в ZIP** для передачи или архивации

### Вкладка «Граф связей»

Визуализация vault как интерактивного графа. Узлы:
- **Продукты** — синие плашки
- **CVE** — круги с цветом по severity, красная обводка у CVE из CISA KEV
- **CWE** — серые ромбы

Рёбра показывают связи «CVE затрагивает продукт» и «CVE является экземпляром CWE». Поддерживаются:
- Перетаскивание узлов и панорамирование фона
- Zoom колесом мыши
- Hover по узлу — tooltip с метаданными
- Клик по узлу — переход к соответствующей заметке
- Фильтры по severity, отображение только KEV, скрытие узлов CWE
- Кнопки центрирования и пересборки layout

## Risk-приоритизация

Приложение вычисляет приоритет уязвимостей не только по CVSS, но и с учётом реальной картины эксплуатации:

| Risk Tier | Условие | Действие |
|---|---|---|
| `critical_now` | CVE присутствует в CISA KEV (активно эксплуатируется) | Патчить срочно |
| `critical_likely` | EPSS ≥ 0.7 (высокая вероятность эксплуатации) | Патчить в течение недели |
| `high` | CVSS ≥ 8.0 или EPSS ≥ 0.3 | Плановый патчинг |
| `medium` | CVSS ≥ 5.0 | Стандартный workflow |
| `low` | Остальное | По возможности |

Это соответствует современным практикам vulnerability management — один CVSS-балл уже не считается достаточным для приоритизации, потому что не отражает реальной вероятности атаки.

## Структура проекта

```
nvd-vault/
├── app.py                          # точка входа
├── requirements.txt
├── README.md
├── LICENSE
├── nvd_vault/
│   ├── core/
│   │   ├── models.py               # dataclasses: Vulnerability, CpeRange
│   │   ├── matcher.py              # CPE-матчинг + сравнение версий
│   │   ├── nvd_client.py           # HTTP-клиент NVD API 2.0
│   │   ├── enrichment.py           # клиенты EPSS API и CISA KEV feed + risk scoring
│   │   ├── inventory.py            # парсинг inventory.json
│   │   ├── markdown_writer.py      # генерация .md заметок
│   │   ├── vault_builder.py        # сборка структуры vault
│   │   ├── search_index.py         # SQLite FTS5 индекс
│   │   ├── graph_builder.py        # узлы и рёбра для cytoscape
│   │   └── dashboard.py            # KPI и агрегаты для дашборда
│   ├── api/
│   │   └── bridge.py               # API доступное из JavaScript
│   └── webui/
│       ├── index.html
│       ├── css/main.css
│       └── js/app.js
└── examples/
    └── sample_inventory.json
```

## NVD API ключ

Без ключа NVD ограничивает запросы: 5 за 30 секунд. Для inventory из 5–10 продуктов достаточно.

С ключом лимит — 50 за 30 секунд. Получение ключа: [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key).

После получения ключа **обязательно активируй его по ссылке из письма** — без активации NVD молча возвращает HTTP 404.

EPSS API и CISA KEV feed работают без аутентификации.

## Ограничения

- **Тестировалось на Windows 11**, инструкции для Linux и macOS приведены, но реальный UX на этих платформах может потребовать доработки
- **Только Application-CPE (`cpe:2.3:a:`)** — уязвимости в OS и hardware (`o:`, `h:`) не покрываются
- **Описания CVE на английском** — без машинного перевода для сохранения технической точности
- **Точность зависит от качества CPE в NVD** — если вендор не проставил диапазоны, версия может не сматчиться

## Troubleshooting

### Windows: ошибка `pythonnet` при `pip install`

```
Failed building wheel for pythonnet
```

Причина: установлен Python 3.14, для которого `pythonnet` ещё не выпустил совместимый wheel. Решение: установить Python 3.13 параллельно и использовать его для venv: `py -3.13 -m venv venv`.

### Windows: окно не открывается, нет ошибок

Возможно, заблокирован запуск через WDAC (Windows Defender Application Control) или Smart App Control. Проверь:

```powershell
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard | `
    Select-Object CodeIntegrityPolicyEnforcementStatus
```

Если значение `2` — WDAC активна. На корпоративных машинах может потребоваться согласование с IT.

### Linux: `ModuleNotFoundError: No module named 'gi'`

Не установлены Python-биндинги к GTK. Установи `python3-gi gir1.2-webkit2-4.1` через системный пакетный менеджер (см. раздел установки).

### Linux: окно открывается, но HTML не рендерится

Версия WebKit устарела или не подхватилась. Проверь установленную версию:

```bash
pkg-config --modversion webkit2gtk-4.1
```

Должна быть 2.40 или выше.

### macOS: Apple Silicon (M1/M2/M3) — `arm64` vs `x86_64`

PyWebView должен установиться нативно под ARM. Если возникают проблемы с зависимостями, попробуй:

```bash
arch -arm64 python3.13 -m venv venv
```

### NVD: HTTP 404 при сканировании с API ключом

API ключ не активирован. После получения ключа на nvd.nist.gov **обязательно перейди по ссылке активации в письме**, иначе NVD молча возвращает 404.

### NVD: HTTP 403 без API ключа

Превышен лимит без ключа (5 запросов / 30 секунд). Решения:
- Получи API ключ для лимита 50 / 30 секунд
- Подожди 30 секунд и повтори

## См. также

- [nvd-scanner](https://github.com/MortalYar/nvd-scanner) — CLI-предшественник этого проекта для одиночного аудита

## Лицензия

MIT — см. [LICENSE](LICENSE).

Источники данных:
- [NVD](https://nvd.nist.gov/) — [Terms of Use](https://nvd.nist.gov/general/terms-of-use)
- [EPSS](https://www.first.org/epss/) от FIRST.org
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
