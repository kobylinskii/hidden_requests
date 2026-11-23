#!/usr/bin/env bash
# Сборка Frida-агентов под frida 17 (в frida 17 убран глобал Java → нужен модуль
# frida-java-bridge). Оборачивает prelude.js/hook.js/activate.js импортом моста и
# компилирует frida-compile в build/<name>.js (bundle, грузится как frida-агент).
# run_stage/activate.py предпочитает build/<name>.js, если он есть (frida 17);
# иначе берёт исходник (frida 16 / arm-стенд курсовой).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p .frida17/src build archivive/build
( cd .frida17 && [ -f package.json ] || npm init -y >/dev/null
  npm i frida-compile frida-java-bridge >/dev/null )
for a in prelude hook activate; do
  source="$a.js"
  output="../build/$a.js"
  if [ "$a" = activate ]; then
    source="archivive/activate.js"
    output="../archivive/build/activate.js"
  fi
  { echo "import Java from 'frida-java-bridge';"; cat "$source"; } > ".frida17/src/$a.js"
  ( cd .frida17 && node_modules/.bin/frida-compile "src/$a.js" -o "$output" )
done
echo "built build/{prelude,hook}.js and archivive/build/activate.js"
