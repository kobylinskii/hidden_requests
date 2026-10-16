#!/usr/bin/env bash
# Сборка Frida-агентов под frida 17 (в frida 17 убран глобал Java → нужен модуль
# frida-java-bridge). Оборачивает prelude.js/hook.js/activate.js импортом моста и
# компилирует frida-compile в build/<name>.js (bundle, грузится как frida-агент).
# run_stage/activate.py предпочитает build/<name>.js, если он есть (frida 17);
# иначе берёт исходник (frida 16 / arm-стенд курсовой).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p .frida17/src build
( cd .frida17 && [ -f package.json ] || npm init -y >/dev/null
  npm i frida-compile frida-java-bridge >/dev/null )
for a in prelude hook activate; do
  { echo "import Java from 'frida-java-bridge';"; cat "$a.js"; } > ".frida17/src/$a.js"
  ( cd .frida17 && node_modules/.bin/frida-compile "src/$a.js" -o "../build/$a.js" )
done
echo "built build/{prelude,hook,activate}.js"
