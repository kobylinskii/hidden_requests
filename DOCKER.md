# Запуск сканера Android APK

[Описание сканера и форматов отчётов](README.md)

## Что понадобится

- APK для статического анализа. Для новой трассы нужен тот же APK на устройстве.
- Docker. Образ использует Debian Bookworm, Python, Java 17, ADB и `unzip`.
- Файл `frida-17.23.3-cp37-abi3-manylinux_2_5_x86_64.whl` в корне проекта и
  `BFScan/target/BFScan-3.1.4.jar`. Оба файла передаются в контекст сборки и
  хранятся отдельно от Git. Этот wheel и приведённая сборка рассчитаны на
  Linux x86-64.
- Устройство или эмулятор с ADB и доступным `frida-server` 17.23.3 для
  записи новой трассы. Архитектура `frida-server` должна соответствовать
  устройству. Офлайн-прогоны с готовой трассой или сравнением обходятся без
  устройства.

Соберите образ из корня проекта. После изменения исходников повторите сборку
образа. После правки JS сначала запустите `./build-agents.sh` на хосте с
Node.js и npm. Он обновляет `build/hook.js` и другие собранные агенты.
При обычном запуске используются уже собранные файлы из репозитория.

```bash
mkdir -p apk out
docker build -t hidden-scanner .
```

## Запись новой трассы

Пример для Linux с ADB-адресом `127.0.0.1:6562` и APK
`apk/demo.apk`. Если устройство использует другой адрес, подставьте его
в `ADB_DEVICE`.

```bash
docker run --rm -it --network host \
  -v "$PWD/apk:/work/apk:ro" -v "$PWD/out:/work/out" \
  -e ADB_DEVICE=127.0.0.1:6562 \
  hidden-scanner /work/apk/demo.apk
```

Сканер подключится к ADB и установит указанный APK, если пакета ещё нет.
Для уже установленного пакета управляйте версией на устройстве отдельно.
Исследуйте приложение и нажмите Ctrl-C. Скрипт завершит запись и построит
отчёты. `TRACE_APPEND=1` добавляет сеанс той же сборки к существующей
завершённой трассе. Обычная запись заменяет файл трассы в выбранном
`OUT_DIR`.

Статика идентифицируется по SHA-256 входного APK, динамика — по SHA-256
установленного base APK. Для split-установки проверяется список
`installed_apks`. Конфигурационные splits без DEX поддерживаются. Если
split содержит код, меняется состав установки или хеши недоступны, трасса
помечается `partial`. Потери событий и преждевременное завершение тоже
видны в `end.reasons`. Если запись нового сеанса завершилась с кодом 3,
`scan.sh` продолжает обработку как частичный прогон. При другой ошибке
трассировщика сканер завершает запуск.

## Офлайн-прогоны в контейнере

Чтобы заново сопоставить каталог с готовой трассой, передайте обе переменные
и используйте пути внутри контейнера. Поместите рядом с каталогом файл
`*_methods.md.meta.json`.

```bash
docker run --rm --network none \
  -v "$PWD/apk:/work/apk:ro" -v "$PWD/out:/work/out" \
  -e OUT_DIR=/work/out/replay \
  -e STATIC_IN=/work/out/demo.local.notes_methods.md \
  -e DYNAMIC_IN=/work/out/demo.local.notes.dynamic.jsonl \
  hidden-scanner /work/apk/demo.apk
```

Чтобы повторить обработку с сохранением статусов исходного сравнения,
передайте `HIDDEN_IN`. Добавьте `REASONS_IN`, если есть совместимый отчёт
стражей по той же сборке и тому же набору объявлений. Для обоих файлов
понадобятся соседние `*.meta.json`.

```bash
docker run --rm --network none \
  -v "$PWD/apk:/work/apk:ro" -v "$PWD/out:/work/out" \
  -e OUT_DIR=/work/out/replay \
  -e HIDDEN_IN=/work/out/demo.local.notes.hidden.jsonl \
  -e REASONS_IN=/work/out/demo.local.notes.reasons.jsonl \
  hidden-scanner /work/apk/demo.apk
```

При смене `SCAN_ALL_PATHS` меняется набор объявлений для отчёта о путях.
Для такого прогона используйте `REASONS_IN` с тем же набором или запустите
анализ графа заново.

## Запуск на хосте

Для офлайн-анализа достаточно Python 3.11 или новее и зависимостей из
`Dockerfile`. Java 17, `unzip` и BFScan JAR нужны при построении нового
каталога. Для записи новой трассы дополнительно нужны ADB и Frida.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install 'androguard==4.1.4' 'networkx>=3,<3.5' loguru requests
PYTHON=.venv/bin/python OUT_DIR=out/replay \
  HIDDEN_IN=out/demo.local.notes.hidden.jsonl \
  bash scan.sh apk/demo.apk
```

Для новой трассы установите клиент Frida из wheel, соответствующего вашему
хосту. Для Linux x86-64 можно использовать тот же файл, что и при сборке
образа.

```bash
.venv/bin/python -m pip install ./frida-17.23.3-cp37-abi3-manylinux_2_5_x86_64.whl
```

Каталог и трассировщик доступны и по отдельности. `trace.py` принимает
`--append`, `--max-restarts` и `--script`.

```bash
PYTHON=.venv/bin/python bash bfscan.sh apk/demo.apk out/demo.local.notes_methods.md
.venv/bin/python trace.py --package demo.local.notes --device 127.0.0.1:6562 \
  --out out/demo.local.notes.dynamic.jsonl
```

## Переменные запуска

| Переменная | Назначение |
|---|---|
| `OUT_DIR` | Выходной каталог. По умолчанию `/work/out` |
| `ADB_DEVICE` | ADB-адрес устройства для новой трассы |
| `STATIC_IN` | Готовый каталог BFScan |
| `DYNAMIC_IN` | Готовая трасса. При отсутствии `STATIC_IN` сканер заново строит каталог |
| `HIDDEN_IN` | Готовое сравнение. При его наличии сканер пропускает сбор каталога и трассы |
| `REASONS_IN` | Совместимый отчёт о путях и стражах |
| `SCAN_ALL_PATHS=1` | Анализ путей для всех объявлений, включая `observed` |
| `TRACE_APPEND=1` | Дописать новую сессию той же сборки |
| `PYTHON` | Интерпретатор для скриптов. По умолчанию `python3` |
| `BFSCAN_JAR` | Путь к JAR при извлечении каталога |

## Результаты и диагностика

В `OUT_DIR` появятся сравнение `*.hidden.jsonl`, примеры BFScan
`*.bodies.jsonl`, срезы аргументов `*.request-slice.jsonl` и отчёты
о путях `*.reasons.jsonl` и `*.reasons.report.txt`. Состав полей описан
в [руководстве по отчётам](README.md#как-читать-отчёты). Сканер печатает
примеры тел в stdout, этапы и статистику в stderr. Метаданные и JSONL
доступны для чтения на хосте.

- Если BFScan исчерпал память, попробует разобрать APK по отдельным DEX.
  Метаданные такого каталога содержат `analysis_mode=per_dex` и
  `status=partial`. Сопоставление может потерять объявления и сведения о DTO.
- При несовпадении сборки сначала сравните SHA-256 переданного APK
  с `build` в каталоге и трассе. Версии пакета для проверки недостаточно.
- При отказе в чтении готового JSONL проверьте файл `*.meta.json`,
  его контрольную сумму и тип артефакта. Для пустого готового сравнения
  метаданные должны указывать `artifact_type=hidden`.
- Чтобы перенести результаты, скопируйте весь `OUT_DIR` со скрытым каталогом
  поколений. Для отдельного JSONL используйте `cp -L` и сохраните его
  `*.meta.json`. Связь отчётов проверяется по `<pkg>.run.json`,
  `build` и `declaration_id`.
