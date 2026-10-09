#!/usr/bin/env bash
# Laboratorio aislado: tcpdump captura credenciales en claro en un login HTTP sin cifrar.
# Credenciales ficticias de laboratorio. Red Docker 'internal', sin salida a Internet.
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p "$PWD/pcap"
docker rm -f ssi-web ssi-tap >/dev/null 2>&1 || true
docker network rm ssi-sniff-net >/dev/null 2>&1 || true

docker network create --internal --subnet 10.20.0.0/16 ssi-sniff-net >/dev/null
# Servidor web de laboratorio que registra el cuerpo del POST /login (HTTP en claro).
docker run -d --name ssi-web --network ssi-sniff-net --ip 10.20.0.10 python:3.12-alpine \
  python3 -c '
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get("Content-Length",0)); self.rfile.read(n)
        self.send_response(200); self.end_headers(); self.wfile.write(b"OK")
    def log_message(self,*a): pass
socketserver.TCPServer(("",80),H).serve_forever()' >/dev/null
sleep 4
# Sniffer en modo promiscuo compartiendo la red del servidor.
docker run -d --name ssi-tap --net=container:ssi-web -v "$PWD/pcap":/cap \
  nicolaka/netshoot sh -c 'tcpdump -i eth0 -s0 "tcp port 80" -w /cap/login.pcap' >/dev/null
sleep 2
echo "== Cliente envía un login por HTTP sin cifrar (credenciales de laboratorio) =="
docker run --rm --network ssi-sniff-net nicolaka/netshoot \
  curl -s -o /dev/null -d "usuario=ana.lopez&password=Verano2026!" http://10.20.0.10/login
sleep 2
docker rm -f ssi-tap >/dev/null
echo "== El atacante lee el cuerpo capturado con tcpdump (texto ASCII) =="
docker run --rm -v "$PWD/pcap":/cap nicolaka/netshoot \
  tcpdump -r /cap/login.pcap -A -nn 2>/dev/null | grep -E "POST|Host:|User-Agent:|usuario=" | sed 's/\.\.\.*//g' | head -10
docker rm -f ssi-web >/dev/null
docker network rm ssi-sniff-net >/dev/null
