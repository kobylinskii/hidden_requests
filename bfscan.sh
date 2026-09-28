#!/usr/bin/env bash
# Извлечение статических HTTP-запросов из APK через BFScan.
#
# Зачем обёртка: на крупном multi-dex APK (TNT Premier — 112 МБ, 10 dex) BFScan
# падает с java.lang.OutOfMemoryError, но при этом ВЫХОДИТ С КОДОМ 0 и оставляет
# молча обрезанный .md. На TNT так потерялось 33 эндпоинта из 172, включая
# 8 в собственном коде приложения — по обрезанному файлу они выглядели бы как
# «скрытые запросы».
#
# Лечится подачей dex-файлов по одному: пиковая память падает на порядок.
# Заодно падение теперь заметно — grep по логу и ненулевой код возврата.
#
#   ./bfscan.sh apk/gpm.tnt_premier.apk [apk/gpm.tnt_premier_methods.md]

set -euo pipefail

APK=${1:?укажите путь к apk}
OUT=${2:-${APK%.apk}_methods.md}
JAR=${BFSCAN_JAR:-$HOME/hidden_requests/requests/BFScan/target/BFScan-3.1.4.jar}

[ -f "$JAR" ] || { echo "нет $JAR — соберите BFScan (mvn package)" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

unzip -q -j "$APK" '*.dex' -d "$WORK"
n=$(ls "$WORK"/*.dex 2>/dev/null | wc -l)
[ "$n" -gt 0 ] || { echo "в $APK нет dex-файлов" >&2; exit 1; }
echo "dex-файлов: $n" >&2

: > "$OUT"
for dex in "$WORK"/*.dex; do
    java -jar "$JAR" "$dex" -m h > "$WORK/log" 2>&1 || true
    if grep -q OutOfMemoryError "$WORK/log"; then
        echo "OutOfMemoryError на $(basename "$dex") — результат неполон" >&2
        exit 1
    fi
    md="${dex%.dex}_methods.md"
    found=0
    if [ -f "$md" ]; then
        cat "$md" >> "$OUT"
        found=$(grep -c '^\*\*Method\*\*' "$md" || true)
    fi
    printf '  %-16s %4s эндпоинтов\n' "$(basename "$dex")" "$found" >&2
done

echo "итого: $(grep -c '^\*\*Method\*\*' "$OUT") -> $OUT" >&2
