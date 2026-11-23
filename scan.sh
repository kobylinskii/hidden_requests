#!/usr/bin/env bash
# BFScan + наблюдения Frida → сравнение → тела BFScan и обратные срезы.
set -euo pipefail

APK=${1:?Использование: scan.sh <path-to.apk>}
[ -f "$APK" ] || { echo "нет файла APK: $APK" >&2; exit 1; }
OUT=${OUT_DIR:-/work/out}
HERE=$(cd "$(dirname "$0")" && pwd)
export PYTHON=${PYTHON:-python3}
PY=$PYTHON
mkdir -p "$OUT"

PKG=$("$PY" -c 'import sys; from androguard.core.apk import APK; from loguru import logger; logger.disable("androguard"); print(APK(sys.argv[1]).get_package())' "$APK")
STATIC=${STATIC_IN:-"$OUT/${PKG}_methods.md"}
DYN=${DYNAMIC_IN:-"$OUT/${PKG}.dynamic.jsonl"}
HIDDEN="$OUT/${PKG}.hidden.jsonl"
REPORT="$OUT/${PKG}.bodies.jsonl"
SLICE="$OUT/${PKG}.request-slice.jsonl"
ARGS=()

if [ -n "${SLICE_IN:-}" ]; then
    echo "Для отчёта BFScan используйте HIDDEN_IN вместо SLICE_IN." >&2
    exit 2
fi
if [ -n "${HIDDEN_IN:-}" ]; then
    ARGS+=(--comparison-in "$HIDDEN_IN")
else
    if [ -z "${STATIC_IN:-}" ]; then
        # A failed collector still publishes a partial artifact for diagnosis.
        "$HERE/bfscan.sh" "$APK" "$STATIC" || echo "BFScan завершился с ошибкой" >&2
    fi
    if [ -z "${DYNAMIC_IN:-}" ]; then
        DEV=${ADB_DEVICE:?задайте ADB_DEVICE или передайте DYNAMIC_IN}
        adb connect "$DEV" >&2 || true
        adb -s "$DEV" wait-for-device
        if ! adb -s "$DEV" shell pm path "$PKG" | grep -q '^package:'; then
            adb -s "$DEV" install -r "$APK" >&2
        fi
        echo "Исследуйте приложение на устройстве. Ctrl-C завершает запись трассы." >&2
        APPEND=()
        if [ "${TRACE_APPEND:-0}" = 1 ]; then
            APPEND+=(--append)
        else
            : > "$DYN"
        fi
        if ! "$PY" "$HERE/trace.py" --package "$PKG" --out "$DYN" --device "$DEV" "${APPEND[@]}" >&2; then
            printf '%s\n' '{"t":"collector_error"}' >> "$DYN"
            echo "Трасса завершена с неполными данными; причины указаны выше и в записи end" >&2
        fi
    fi
    ARGS+=(--catalog "$STATIC" --trace "$DYN")
fi

"$PY" "$HERE/request_pipeline.py" --apk "$APK" --comparison "$HIDDEN" \
    --out "$REPORT" --request-slice "$SLICE" "${ARGS[@]}"
echo "JSON-отчёт: $REPORT" >&2
echo "Обратные срезы: $SLICE" >&2
