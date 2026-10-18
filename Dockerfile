# Сканер скрытых HTTP-запросов — весь инструментарий в одном образе.
# Устройство/эмулятор НЕ в контейнере (Genymotion — GUI-VM на хосте, пентестер
# кликает в его окне); контейнер цепляется к нему по `adb connect $ADB_DEVICE`,
# frida общается с frida-server на устройстве через adb. См. DOCKER.md.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        openjdk-17-jre-headless python3 python3-venv python3-pip \
        adb unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# сначала зависимости (кэш слоёв): frida-колесо + python-пакеты
COPY frida-17.23.3-cp37-abi3-manylinux_2_5_x86_64.whl /app/
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir \
        /app/frida-17.23.3-cp37-abi3-manylinux_2_5_x86_64.whl \
        androguard==4.1.4 "networkx>=3,<3.5" loguru requests
ENV PATH="/opt/venv/bin:$PATH"

# код + собранные frida17-агенты (build/) + BFScan jar — всё из репозитория
COPY . /app
RUN chmod +x /app/scan.sh /app/bfscan.sh

# APK и артефакты монтируются/пишутся в /work (volume)
ENV ADB_DEVICE=host.docker.internal:6562 \
    OUT_DIR=/work/out
VOLUME ["/work"]
ENTRYPOINT ["/app/scan.sh"]
