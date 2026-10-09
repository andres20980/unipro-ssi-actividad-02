#!/usr/bin/env bash
# Laboratorio aislado: escaneo SYN con nmap detectado por Suricata.
# Red Docker 'internal' (sin salida a Internet). Solo contenedores propios.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p "$PWD/pcap"

docker rm -f ssi-target ssi-sniff >/dev/null 2>&1 || true
docker network rm ssi-lab >/dev/null 2>&1 || true

docker network create --internal --subnet 10.10.0.0/16 ssi-lab >/dev/null
# Objetivo: varios puertos abiertos (22, 80, 443, 3306) servidos con socat.
docker run -d --name ssi-target --network ssi-lab --ip 10.10.1.5 alpine:3.20 \
  sh -c 'apk add --no-cache socat >/dev/null 2>&1; for p in 22 80 443 3306; do socat TCP-LISTEN:$p,fork,reuseaddr - & done; sleep 600' >/dev/null
sleep 6
# Sniffer compartiendo la pila de red del objetivo -> ve todo su tráfico.
docker run -d --name ssi-sniff --net=container:ssi-target -v "$PWD/pcap":/cap \
  nicolaka/netshoot tcpdump -i eth0 -w /cap/scan.pcap >/dev/null
sleep 2
echo "== Escaneo SYN (nmap -sS) desde el contenedor atacante =="
docker run --rm --network ssi-lab --ip 10.10.66.66 instrumentisto/nmap \
  -sS -p 1-1000 --max-retries 1 10.10.1.5 2>&1 | grep -E "Nmap scan|PORT|open|Nmap done" | head -15
sleep 2
docker rm -f ssi-sniff >/dev/null
echo
echo "== Suricata analiza el pcap con las reglas locales =="
docker run --rm --entrypoint sh -v "$PWD/suricata":/lab -v "$PWD/pcap":/cap -v "$PWD/capturas":/out \
  jasonish/suricata:7.0 -c '
    suricata -r /cap/scan.pcap -S /lab/local.rules \
      --set "vars.address-groups.HOME_NET=[10.10.0.0/16]" \
      --set "vars.address-groups.EXTERNAL_NET=any" -l /out >/dev/null 2>&1
    echo "--- fast.log (alertas generadas) ---"
    grep "LOCAL SCAN" /out/fast.log | head -3
    echo
    echo "Total de alertas de escaneo:" $(grep -c "LOCAL SCAN" /out/fast.log)'
docker rm -f ssi-target >/dev/null
docker network rm ssi-lab >/dev/null
