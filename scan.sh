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
# Полный отчёт — в файл, в терминал — только сводка (не засорять выводом).
say "4/6  Выделение скрытых запросов (diff)"
$PY "$HERE/diff.py" --static "$STATIC" --dynamic "$DYN" --out "$HIDDEN" \
    > "$OUT/${PKG}.hidden.report.txt" 2>/dev/null
$PY - "$STATIC" "$HIDDEN" >&2 <<'PY'
import json, re, sys
stat = len(re.findall(r'^\*\*Method\*\*', open(sys.argv[1], encoding="utf-8").read(), re.M))
h = n = nr = 0
for l in open(sys.argv[2], encoding="utf-8"):
    st = json.loads(l).get("status")
    h += st == "hidden"; n += st == "not_in_static"; nr += st == "non_retrofit"
print(f"  скрытых запросов: {h}  (из {stat} статических записей) | "
      f"вызвано-но-нет-в-статике: {n} | вне retrofit: {nr}")
PY

# ── 5. Срез скрытых запросов ────────────────────────────────────────────────
# Срез объёмный (call-sites/стражи/провенанс по каждому ключу) — в файл;
# в терминал только сводка.
say "5/6  Статический срез скрытых запросов (slice)"
# stdout (огромный отчёт среза) — в /dev/null; stderr (прогресс) — в терминал.
$PY "$HERE/slice.py" --hidden "$HIDDEN" --apk "$APK" --out "$SLICE" >/dev/null
$PY - "$SLICE" >&2 <<'PY'
import json, sys
tot = reached = exact = 0
for l in open(sys.argv[1], encoding="utf-8"):
    r = json.loads(l); tot += 1
    reached += bool(r.get("reached")); exact += bool(r.get("activation_exact"))
print(f"  срез построен: {tot} ключей | достижимы в коде: {reached} | "
      f"напрямую активируемы (activation_exact): {exact}")
PY

# ── 6. Принудительная активация ──────────────────────────────────────────────
# --recurse-args: полное тело с продюсерами/заглушками; --skip-dx: без повторной
# тяжёлой загрузки APK (срез уже несёт типы/рецепты/провенанс). Прогресс по
# ключам печатает сам activate.py; итоговый отчёт — ниже.
say "6/6  Принудительный вызов скрытых запросов (activate)"
# stdout (итоговый отчёт) — в /dev/null (покажем из файла ниже), stderr
# (прогресс по ключам) — в терминал.
$PY "$HERE/activate.py" --slice "$SLICE" --apk "$APK" --package "$PKG" \
    --backend mech --recurse-args --skip-dx --hidden "$HIDDEN" \
    --out "$ACT" ${ACT_ATTACH:+--attach} >/dev/null

say "ГОТОВО — отчёты в $OUT"
echo "  скрытые запросы:        $HIDDEN  (+ .report.txt)" >&2
echo "  активация (итог):       $ACT  (+ .report.txt)" >&2
echo >&2
# финальный отчёт активации в stdout (какие скрытые, сколько дёрнуто, с какими данными)
cat "${ACT%.jsonl}.report.txt" 2>/dev/null || true
