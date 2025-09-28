# Парсер Android logcat

Утилита на Python для разработчиков Android: удобный парсер логов `logcat` с поддержкой фильтров, цветного вывода и экспорта в JSON/CSV.

## Возможности

- 📱 Чтение логов напрямую из **ADB** или из сохранённого файла.
- 🎨 Красивый цветной вывод в терминале (с уровнями V/D/I/W/E/F).
- 🔍 Гибкая фильтрация:
  - по уровню (`--min-level`),
  - по тегам (`--tag`),
  - по PID,
  - по регулярным выражениям (`--grep`),
  - по подстроке (`--contains`).
- 💾 Экспорт в **JSON** или **CSV** для последующего анализа.
- ⚡ Поддержка форматов `time`, `threadtime`, `epoch`.
- 🔧 Минимальные зависимости (работает из коробки, опционально — `colorama`).

---

## Установка

1. Убедитесь, что установлен **Python 3.9+**.
2. Установите **ADB** (Android Platform Tools) и добавьте его в `PATH`.
3. Клонируйте репозиторий:

```bash
git clone https://github.com/Android-RU/Android-Logcat-Parser.git
cd Android-Logcat-Parser
````

4. (Необязательно) Установите зависимости:

```bash
pip install colorama python-dateutil
```

---

## Использование

Запуск:

```bash
python logcat.py [OPTIONS]
```

### Чтение из ADB

```bash
python logcat.py --adb --min-level W
```

Покажет только предупреждения и ошибки с подключённого устройства.

### Чтение из файла

```bash
python logcat.py --input raw.log --format time --json out.json
```

Разбор сохранённого файла с сохранением результата в JSON.

### Фильтрация по тегу

```bash
python logcat.py --adb --tag ActivityManager
```

### Поиск текста в логах

```bash
python logcat.py --input raw.log --contains "ANR"
```

### Экспорт в CSV

```bash
python logcat.py --adb --csv logs.csv
```

---

## Аргументы

### Источник логов

* `--adb` — читать из ADB.
* `--input FILE` — читать из файла.
* `--serial SERIAL` — выбрать устройство по серийному номеру.
* `--adb-path PATH` — путь к бинарю ADB.
* `--buffer {main,system,events,radio,crash,all}` — выбор буфера (по умолчанию `main`).
* `--format {time,threadtime,epoch}` — формат строк (по умолчанию `threadtime`).
* `--clear` — очистить буфер перед стартом.

### Фильтры

* `--min-level {V,D,I,W,E,F}` — минимальный уровень логов.
* `--tag TAG1 TAG2` — фильтрация по тегам.
* `--grep REGEX` — фильтрация по регулярному выражению.
* `--contains TEXT` — поиск подстроки.
* `-i, --ignore-case` — игнорировать регистр.
* `--pid PID` — фильтрация по PID.

### Вывод

* `--no-color` — отключить цвета.
* `--json FILE` — сохранить в JSON.
* `--csv FILE` — сохранить в CSV.
* `--json-indent N` — красивый JSON с отступами.

---

## Примеры

* Онлайн фильтр по пакету и уровню:

  ```bash
  python logcat.py --adb --min-level E --json errors.json
  ```

* Разбор файла и поиск ANR:

  ```bash
  python logcat.py --input raw.log --grep "ANR"
  ```

* Живой просмотр только ошибок из всех буферов:

  ```bash
  python logcat.py --adb --buffer all --min-level E
  ```

---

## Структура репозитория

```
Android-Logcat-Parser/
├── logcat.py      # основной скрипт
├── README.md      # описание
└── LICENSE        # лицензия (MIT)
```

---

## Лицензия

Проект распространяется по лицензии **MIT**.
Вы можете свободно использовать, изменять и распространять данный код.

Полный текст лицензии: [LICENSE](LICENSE)
