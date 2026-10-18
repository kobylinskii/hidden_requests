#!/usr/bin/env bash
# Сканер скрытых HTTP-запросов — оркестратор 6 шагов (см. DOCKER.md).
#   вход:  APK-файл (аргумент)
#   выход: отчёт в $OUT_DIR — какие запросы скрытые, сколько удалось дёрнуть и
#          с какими данными.
# Устройство/эмулятор — на хосте, контейнер цепляется по $ADB_DEVICE.
set -euo pipefail

APK=${1:?Использование: scan.sh <path-to.apk>   (устройство — через ADB_DEVICE=host:port)}
[ -f "$APK" ] || { echo "нет файла APK: $APK" >&2; exit 1; }
OUT=${OUT_DIR:-/work/out}; mkdir -p "$OUT"
DEV=${ADB_DEVICE:?не задан ADB_DEVICE (host:port работающего frida-server-устройства)}
HERE=$(cd "$(dirname "$0")" && pwd)
PY=python3

say() { printf '\n\033[1;36m=== %s ===\033[0m\n' "$*" >&2; }

# ── 0. Устройство ───────────────────────────────────────────────────────────
say "0/6  Подключение к устройству $DEV"
adb connect "$DEV" >&2 || true
adb -s "$DEV" wait-for-device
adb -s "$DEV" shell 'ps -A 2>/dev/null | grep -q frida-server' \
    || echo "ВНИМАНИЕ: на устройстве не вижу frida-server — подними его перед динамическими шагами" >&2

# ── 1. Пакет из APK ──────────────────────────────────────────────────────────
say "1/6  Определение пакета из APK"
PKG=$($PY -c "import sys; sys.path.insert(0,'$HERE'); from activate import _package_of; print(_package_of('$APK'))")
echo "пакет: $PKG" >&2
adb -s "$DEV" shell pm list packages 2>/dev/null | grep -q "$PKG" \
    || { echo "ставлю APK на устройство..." >&2; adb -s "$DEV" install -r "$APK" >&2; }

STATIC="$OUT/${PKG}_methods.md"
DYN="$OUT/${PKG}.dynamic.jsonl"
HIDDEN="$OUT/${PKG}.hidden.jsonl"
SLICE="$OUT/${PKG}.slice.jsonl"
ACT="$OUT/${PKG}.activation.jsonl"

# ── 2. Статика: все HTTP-эндпоинты из кода ──────────────────────────────────
say "2/6  Статическое извлечение эндпоинтов (BFScan)"
"$HERE/bfscan.sh" "$APK" "$STATIC" >&2

# ── 3. Сбор трафика пентестером до насыщения ────────────────────────────────
say "3/6  СБОР ТРАФИКА"
cat >&2 <<EOF

  ▶ НАЧИНАЙТЕ СБОР ТРАФИКА ДО НАСЫЩЕНИЯ.
    Исследуйте приложение в эмуляторе руками — открывайте все экраны, вкладки,
    сценарии, пока в логе не перестанут появляться новые запросы.
    Нажмите Ctrl-C в этом терминале, когда наступит насыщение.

EOF
$PY "$HERE/trace.py" --package "$PKG" --out "$DYN" ${TRACE_APPEND:+--append} >&2 || true
[ -s "$DYN" ] || { echo "трафик не собран ($DYN пуст) — прерываю" >&2; exit 1; }

# ── 4. Скрытые запросы: статика ∖ динамика ──────────────────────────────────
say "4/6  Выделение скрытых запросов (diff)"
$PY "$HERE/diff.py" --static "$STATIC" --dynamic "$DYN" --out "$HIDDEN" >&2

# ── 5. Срез скрытых запросов ────────────────────────────────────────────────
say "5/6  Статический срез скрытых запросов (slice)"
$PY "$HERE/slice.py" --hidden "$HIDDEN" --apk "$APK" --out "$SLICE" >&2

# ── 6. Принудительная активация ──────────────────────────────────────────────
say "6/6  Принудительный вызов скрытых запросов (activate)"
# --recurse-args: полное тело с продюсерами/заглушками; --skip-dx: без повторной
# тяжёлой загрузки APK (срез уже несёт типы/рецепты/провенанс).
$PY "$HERE/activate.py" --slice "$SLICE" --apk "$APK" --package "$PKG" \
    --backend mech --recurse-args --skip-dx --hidden "$HIDDEN" \
    --out "$ACT" ${ACT_ATTACH:+--attach} >&2

say "ГОТОВО — отчёты в $OUT"
echo "  скрытые запросы:        $HIDDEN  (+ .report.txt)" >&2
echo "  активация (итог):       $ACT  (+ .report.txt)" >&2
echo >&2
# финальный отчёт активации в stdout (какие скрытые, сколько дёрнуто, с какими данными)
cat "${ACT%.jsonl}.report.txt" 2>/dev/null || true
