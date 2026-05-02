# NVD Vault

[English](README.md) · **Русский**

Локальное desktop-приложение для аудита уязвимостей по инвентарю open-source ПО с приоритизацией патчинга на основе CVSS, EPSS и CISA KEV.

На вход подаётся `inventory.json` или SBOM (CycloneDX / SPDX). На выходе — **vault** в формате Markdown-заметок со ссылками между CVE / продуктами / CWE, плюс встроенный браузер с поиском, графом связей и аналитическим дашбордом.

![Python](https://img.shields.io/badge/python-3.11+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-windows-lightgrey)
![CI](https://github.com/MortalYar/nvd-vault/actions/workflows/tests.yml/badge.svg)

---

## Зачем это нужно

Стандартный сценарий безопасника: «У нас Kibana 8.19, Logstash 8.19, OpenSSL 3.0 и nginx 1.24 — что у нас критично, что патчить в первую очередь?»

NVD Vault отвечает на этот вопрос автоматически:

1. Берёт список ПО и версии.
2. Дёргает NVD API, находит все CVE для каждой связки.
3. Обогащает результаты данными EPSS (вероятность эксплуатации) и CISA KEV (известная активная эксплуатация).
4. Формирует приоритизированный список с понятными ярлыками `critical_now` / `critical_likely` / `high` / `medium` / `low`.
5. Сохраняет всё локально в Markdown — можно открыть в Obsidian, отдать аудиторам или просмотреть во встроенном UI.

В отличие от веб-сервисов вроде Snyk или GitHub Dependabot, **всё работает локально** — инвентарь не покидает машину, отправляется только запрос к публичному NVD API с именами компонентов.

---

## Возможности

- Сборка vault из `inventory.json` или SBOM (CycloneDX / SPDX)
- Автоматический поиск vendor через NVD CPE Dictionary
- Точное CPE 2.3 матчинг с поддержкой версионных диапазонов и pre-release-версий
- Risk-based приоритизация: **CVSS + EPSS + CISA KEV**
- Markdown-граф знаний со связями `[[wiki-links]]` между CVE, Product и CWE
- Интерактивный дашборд с KPI и риск-аналитикой
- Полнотекстовый поиск через SQLite FTS5
- Визуализация графа связей через Cytoscape.js (с экспортом в PNG)
- Экспорт vault как ZIP-архив
- GUI и CLI режимы
- Кэширование CISA KEV-каталога (TTL 1 час) — быстрые повторные сканирования
- Корректная обработка rate-limits NVD без падений

---

## Быстрый старт

### Установка

```bash
git clone https://github.com/MortalYar/nvd-vault.git
cd nvd-vault
python -m pip install -e ".[dev]"
```

> Требуется Python 3.11 или новее. Протестировано на 3.11, 3.12, 3.13.

### Запуск GUI

```bash
nvd-vault
```

или равнозначно:

```bash
python app.py
```

### Сборка vault через CLI

```bash
nvd-vault build examples/sample_inventory.json --out ./vault
```

Если `--out` не указан — путь будет запрошен интерактивно.

---

## Формат inventory

```json
{
  "vault_name": "Корпоративный_ELK_кластер",
  "products": [
    { "name": "kibana", "version": "8.19.9", "vendor": "elastic" },
    { "name": "logstash", "version": "8.19.5", "vendor": "elastic" },
    { "name": "openssl", "version": "3.0.11", "vendor": "openssl" }
  ]
}
```

Поле `vendor` опционально — если его нет, NVD Vault попытается найти vendor автоматически через CPE Dictionary. Если кандидатов несколько, GUI откроет диалог выбора.

### Поддерживаемые форматы SBOM

- **CycloneDX JSON** (`bomFormat: "CycloneDX"`)
- **SPDX JSON** (поле `spdxVersion`)

```bash
nvd-vault build sbom.cyclonedx.json --input-format sbom --out ./vault
```

Авто-детект формата работает по содержимому JSON:

```bash
nvd-vault build sbom.cyclonedx.json --out ./vault
```

---

## Структура сгенерированного vault

```text
vault/
├── meta.json                  # метаданные vault (имя, дата сборки, статистика)
├── search.db                  # SQLite-индекс для FTS5
├── cves/
│   ├── CVE-2024-XXXXX.md
│   └── ...
├── products/
│   ├── kibana.md              # сводка уязвимостей по продукту
│   └── ...
└── cwes/
    ├── CWE-79.md
    └── ...
```

Каждая `.md`-заметка содержит YAML frontmatter с метаданными (CVSS, EPSS, KEV, ransomware-флаг, тип риска) и человекочитаемое тело со ссылками `[[на другие заметки]]`.

Vault полностью совместим с **Obsidian** — можно открыть папку как Obsidian Vault и пользоваться его возможностями (граф, поиск, плагины) поверх.

---

## Модель приоритизации рисков

| Тier | Условие | Что делать |
|---|---|---|
| `critical_now` | Уязвимость есть в каталоге CISA KEV (активно эксплуатируется в реальных атаках) | **Патчить срочно**, по возможности немедленно |
| `critical_likely` | EPSS ≥ 0.7 (высокая вероятность эксплуатации в ближайшие 30 дней) | Патчить в течение нескольких дней |
| `high` | CVSS ≥ 8.0 или EPSS ≥ 0.3 | Включить в плановый патчинг |
| `medium` | CVSS ≥ 5.0 | Стандартный workflow |
| `low` | Всё остальное | По возможности, без срочности |

### Что значат эти аббревиатуры

- **CVSS** (Common Vulnerability Scoring System) — стандартная оценка серьёзности уязвимости от 0.0 до 10.0. Учитывает атак-вектор, сложность эксплуатации, требуемые привилегии и влияние на confidentiality/integrity/availability. Сам по себе CVSS говорит «насколько *плохо*, если эксплуатируют», но не «насколько *вероятно*, что эксплуатируют».
- **EPSS** (Exploit Prediction Scoring System) — вероятность эксплуатации в ближайшие 30 дней, число от 0.0 до 1.0. Считается ежедневно командой FIRST на основе ML-модели по реальным атакам, exploit kits, упоминаниям в Twitter/GitHub. Дополняет CVSS: высокий CVSS + низкий EPSS — «теоретически опасно, но никто не атакует»; низкий CVSS + высокий EPSS — «эксплуатируют прямо сейчас».
- **CISA KEV** (Known Exploited Vulnerabilities) — каталог уязвимостей, для которых **подтверждена активная эксплуатация**. Поддерживается американским агентством CISA. Если CVE в KEV — это значит, что её используют в реальных атаках, и патчить надо вчера.

---

## Получение API-ключа NVD

**Настоятельно рекомендуется** для любых сборок крупнее 5–10 продуктов.

| Без ключа | С ключом |
|---|---|
| 5 запросов / 30 секунд | 50 запросов / 30 секунд |
| Сборка 20 продуктов ≈ 2 минуты | Сборка 20 продуктов ≈ 12 секунд |

Бесплатный ключ можно получить здесь:

> https://nvd.nist.gov/developers/request-an-api-key

Ключ приходит на email через несколько минут. Использование:

### PowerShell (Windows)

```powershell
$env:NVD_API_KEY="your_api_key_here"
```

Или постоянно:

```powershell
[Environment]::SetEnvironmentVariable("NVD_API_KEY", "your_api_key_here", "User")
```

### Linux / macOS

```bash
export NVD_API_KEY="your_api_key_here"
```

В CLI можно передать ключ напрямую:

```bash
nvd-vault build inventory.json --api-key your_api_key_here --out ./vault
```

---

## Интерфейс

Приложение состоит из четырёх вкладок:

- **Сборка Vault** — редактор inventory + запуск сборки. Можно загрузить готовый JSON или собрать список руками с автопоиском vendor через NVD.
- **Дашборд** — KPI по vault'у (всего CVE, эксплуатируется, ransomware, просрочено CISA), топы продуктов и CWE, план патчинга.
- **Граф связей** — Cytoscape-визуализация связей между CVE, продуктами и CWE. Можно фильтровать по риск-тиру и экспортировать в PNG.
- **Просмотр Vault** — браузер заметок с подсветкой риск-тиров, иконками KEV/ransomware, полнотекстовым поиском и переходами по wiki-links.

---

## Сравнение с другими инструментами

| Инструмент | Тип | Inventory | Risk score | Локальная работа | Open source |
|---|---|---|---|---|---|
| **NVD Vault** | Desktop GUI | manual JSON / SBOM | CVSS + EPSS + KEV | да | да (MIT) |
| Snyk | SaaS | git/SBOM auto | свой score | нет | freemium |
| GitHub Dependabot | SaaS | repo auto | CVSS | нет | да (для public repo) |
| OWASP Dependency-Check | CLI | maven/gradle/npm/etc. | CVSS | да | да |
| Trivy | CLI | container/SBOM/repo | CVSS | да | да |
| Grype | CLI | SBOM | CVSS | да | да |
| Vulners | SaaS | manual API | CVSS+exploit | нет | freemium |

**Когда выбирать NVD Vault:**
- Нужен **локальный** аудит без отправки данных в облако.
- Требуется приоритизация по EPSS+KEV, а не только CVSS.
- Хочется не просто список CVE, а **связанные Markdown-заметки** для последующей работы (отчёт, тикет в трекер, разбор).
- Inventory — это «список ПО на нескольких серверах» (а не build-артефакт).

**Когда выбирать что-то другое:**
- Нужна интеграция в CI/CD на каждый pull request → Trivy/Grype/Dependabot.
- Сканирование Docker-образов → Trivy/Grype.
- Java/Node-проекты с зависимостями из package manager → OWASP Dependency-Check.
- Корпоративный сервис с дашбордом для всей команды → Snyk/Vulners/тематический enterprise.

---

## FAQ

### Как часто обновлять vault?

Каждый раз, когда меняется состав ПО или хочется получить свежие данные. NVD обновляет CVE-данные **ежедневно**, EPSS и KEV — тоже. Перестроить vault для inventory из 30 продуктов с API-ключом занимает 30–60 секунд.

### NVD недоступен / 403 / медленно работает

NVD периодически бывает недоступен. NVD Vault корректно обрабатывает rate-limits (5 запросов/30 сек без ключа, 50 с ключом) и автоматически делает повторы при 5xx-ошибках. Если **постоянно** получаешь 403 без ключа — получи ключ (см. выше).

Если NVD заблокирован на сетевом уровне — попробуй с VPN. Прямой обходной канал через сторонние зеркала NVD Vault не использует.

### Работает ли без интернета?

После сборки — **да**: просмотр vault, граф, поиск, экспорт ZIP не требуют сети. Сама сборка требует доступа к `services.nvd.nist.gov`, `api.first.org` (EPSS) и `cisa.gov` (KEV).

UI частично завязан на Google Fonts CDN — при отсутствии интернета шрифты упадут на системные дефолтные, но функционально всё продолжит работать. JS-библиотеки (cytoscape, marked) уже встроены локально.

### Падает с `ImportError: webview` при старте

Не активирован virtualenv или не установлены зависимости:

```powershell
# Windows PowerShell
.\venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

### Vault показывает «0 продуктов, 0 CVE»

Скорее всего, vendor не определился автоматически. Возможные причины:
1. Имя продукта не совпадает с тем, как NVD его называет (например, `apache` vs `httpd`). Открой <https://nvd.nist.gov/products/cpe/search>, найди свой продукт там, посмотри как он называется в CPE и поправь inventory.
2. Vendor отсутствует в указанном поле, и автопоиск ничего не нашёл. Уточни вручную через GUI (кнопка с лупой рядом с полем vendor).
3. Версия указана в формате, который NVD не понимает (например, кастомные суффиксы дистрибутива). Попробуй базовую версию без суффиксов.

### Что не так с моими русскими именами в JSON?

Никаких проблем — поддерживается. Если используешь спецсимволы (запятые, скобки) в значениях — они корректно экранируются в YAML frontmatter заметок.

### Можно ли использовать в коммерческом проекте?

Да, лицензия MIT.

### Сравнение версий — корректно ли работает?

Используется `packaging.version` (PEP 440), что корректно обрабатывает большинство open-source-схем включая pre-release (`1.0.0-rc2 < 1.0.0-rc10 < 1.0.0`). Для экзотических версий (например, дистрибутивных вроде `5.7.32-0ubuntu0.18.04.1`) есть fallback-парсер. Если столкнулся со случаем, который сравнивается неправильно — открой issue.

### Что делать с большим количеством critical_now?

`critical_now` означает «активная эксплуатация подтверждена CISA». Эти уязвимости — приоритет №1 даже если CVSS не максимальный. Патчить в порядке появления у тебя в инфраструктуре, начиная с систем, доступных извне.

---

## Troubleshooting

**Проблема:** при запуске `python app.py` открывается пустое чёрное окно
**Решение:** проверь, что папка `nvd_vault/webui/vendor/` не пуста (там должны быть 5 JS-файлов: marked, cytoscape и cose-bilkent-плагины). Если пусто — склонируй заново или скачай файлы согласно ссылкам в шапке `vendor/`.

**Проблема:** `ModuleNotFoundError: No module named 'packaging'`
**Решение:** ты обновился из старой версии. Запусти `pip install -e ".[dev]"` ещё раз — обновятся зависимости.

**Проблема:** все CVE имеют tier `low`, хотя должны быть critical
**Решение:** обогащение EPSS/KEV отвалилось. Проверь, что `api.first.org` и `cisa.gov` доступны с твоей сети. В логах при сборке (`logger.warning`) будет видно, если запросы падали.

**Проблема:** сборка vault зависает на одном продукте
**Решение:** скорее всего, у этого продукта в NVD очень много CVE (тысячи), и пагинация занимает время. С API-ключом — заметно быстрее. Можно посмотреть прогресс в логах GUI (вкладка Сборка → лог внизу).

**Проблема:** граф пустой или непонятный
**Решение:** граф рисуется только если в vault есть **связи** между заметками (через `[[wiki-link]]`). Если у тебя только продукты без CVE — связей нет, граф пустой. Это нормально.

---

## Разработка

### Тесты

```bash
python -m pytest -v
```

CI настроен на GitHub Actions, прогон на каждый push / PR.

### Структура проекта

```text
nvd-vault/
├── app.py                   # точка входа (CLI + GUI)
├── nvd_vault/
│   ├── core/                # бизнес-логика
│   │   ├── nvd_client.py    # HTTP-клиент NVD API
│   │   ├── enrichment.py    # EPSS, KEV, risk score
│   │   ├── matcher.py       # CPE 2.3 + version comparison
│   │   ├── frontmatter.py   # YAML frontmatter parser
│   │   ├── vault_builder.py # оркестратор сборки
│   │   ├── markdown_writer.py
│   │   ├── dashboard.py
│   │   ├── graph_builder.py
│   │   ├── search_index.py  # SQLite FTS5
│   │   ├── remediation.py
│   │   ├── inventory.py     # парсинг inventory.json
│   │   └── sbom.py          # парсинг CycloneDX/SPDX
│   ├── api/
│   │   └── bridge.py        # JS↔Python API через pywebview
│   └── webui/
│       ├── index.html
│       ├── css/
│       ├── js/
│       └── vendor/          # vendored cytoscape, marked
├── tests/
└── examples/                # примеры inventory и SBOM
```

### Внести вклад

PR-ы приветствуются. Перед отправкой:
1. Прогоните тесты (`pytest`).
2. Если меняли логику — добавьте тест.
3. Описание PR — на любом из языков (RU/EN).

---

## Ограничения

- Работает с **Application CPE** (`cpe:2.3:a:`). OS-CPE и Hardware-CPE не поддерживаются.
- Качество результатов зависит от **полноты CPE-разметки в NVD**. Если NVD не присвоил продукту CPE — vault его не увидит.
- Описания CVE остаются на **английском** (как они в NVD).
- Основная разработка и тестирование — на **Windows 11**. На Linux/macOS должно работать (pywebview кросс-платформенный), но менее протестировано.
- **Не предназначен для аудита Docker-образов** — для этого Trivy/Grype лучше.

---

## Связанные проекты

- [nvd-scanner](https://github.com/MortalYar/nvd-scanner) — CLI-предшественник этого проекта

---

## Лицензия

MIT — см. [LICENSE](LICENSE).
