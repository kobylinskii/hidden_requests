#!/usr/bin/env bash
# Извлечение статических HTTP-запросов через BFScan с учётом меж-DEX ссылок.
# При нехватке памяти повторяем анализ по одному DEX и отмечаем каталог как partial.
#   ./bfscan.sh <app.apk> [methods.md]

set -euo pipefail

APK=${1:?укажите путь к apk}
OUT=${2:-${APK%.apk}_methods.md}
HERE=$(cd "$(dirname "$0")" && pwd)
JAR=${BFSCAN_JAR:-$HERE/BFScan/target/BFScan-3.1.4.jar}
PYTHON=${PYTHON:-python3}

if [[ "$OUT" -ef "$APK" || "$OUT.meta.json" -ef "$APK" ||
      "$OUT" -ef "$JAR" || "$OUT.meta.json" -ef "$JAR" ]]; then
    echo "Каталог и его метаданные должны отличаться от входных файлов" >&2
    exit 1
fi

WORK=$(mktemp -d)
MODE=whole_apk
STATUS=partial
BUILD_INPUT=$APK
: > "$WORK/combined.md"

finish() {
    local code=$?
    if (( code != 0 )); then
        STATUS=partial
    fi
    "$PYTHON" "$HERE/request_artifacts.py" "$BUILD_INPUT" "$OUT" "$STATUS" \
        --source "$WORK/combined.md" --analysis-mode "$MODE" || code=1
    rm -rf -- "$WORK"
    exit "$code"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

run_bfscan() {
    local input=$1 code=0
    java -jar "$JAR" "$input" -m h > "$WORK/log" 2>&1 || code=$?
    if grep -q 'OutOfMemoryError' "$WORK/log"; then
        echo "BFScan: OutOfMemoryError (${input##*/})" >&2
        return 2
    fi
    # BFScan catches Throwable at the input-file boundary and can exit zero.
    if (( code != 0 )) || grep -Fq "Error processing file ${input##*/}" "$WORK/log" ||
       grep -Eq 'Exception in thread|Fatal error|java\.lang\.[[:alnum:]$]+Error([:[:space:]]|$)' "$WORK/log" ||
       [[ ! -f "${input%.*}_methods.md" ]]; then
        cat "$WORK/log" >&2
        echo "BFScan не завершил обработку ${input##*/}" >&2
        return 1
    fi
}

[[ -f "$JAR" ]] || { echo "нет $JAR — соберите BFScan (mvn package)" >&2; exit 1; }
# BFScan writes its reports next to the input. Keep all its files private to this run.
cp -- "$APK" "$WORK/input.apk"
BUILD_INPUT="$WORK/input.apk"
unzip -Z1 "$BUILD_INPUT" '*.dex' > /dev/null || { echo "в $APK нет dex-файлов" >&2; exit 1; }

if run_bfscan "$BUILD_INPUT"; then
    mv -- "$WORK/input_methods.md" "$WORK/combined.md"
    STATUS=complete
elif [[ $? == 2 ]]; then
    MODE=per_dex
    echo "Повтор по DEX: меж-DEX типы и ресурсы APK могут быть недоступны" >&2
    mkdir "$WORK/dex"
    unzip -q -j "$BUILD_INPUT" '*.dex' -d "$WORK/dex"
    for dex in "$WORK"/dex/*.dex; do
        run_bfscan "$dex" || exit 1
        cat "${dex%.dex}_methods.md" >> "$WORK/combined.md"
    done
else
    exit 1
fi
echo "BFScan ($MODE, $STATUS) -> $OUT" >&2
