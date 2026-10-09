#!/usr/bin/env bash
# Laboratorio forense (datos simulados). Correlaciona auth.log y access.log del 15-may 03:14.
set -euo pipefail
cd "$(dirname "$0")"

echo "=== 1) Accesos SSH fallidos/aceptados ==="
grep -E "Failed|Accepted" auth.log | awk '{print $1,$2,$3, ($5=="password"?$4:$6), "usuario="$(NF-5), $(NF-3)}'

echo; echo "=== 2) Fallos por IP (candidata a fuerza bruta) ==="
grep "Failed password" auth.log | grep -oE "from [0-9.]+" | awk '{print $2}' | sort | uniq -c | sort -rn

echo; echo "=== 3) IPs en auth.log que TAMBIEN aparecen en access.log (join) ==="
join <(grep "Failed password" auth.log | grep -oE "[0-9.]+$|from [0-9.]+" | awk '{print $NF}' | sort -u) \
     <(awk '{print $1}' access.log | sort -u)

echo; echo "=== 4) Linea temporal unificada del incidente ==="
{
  awk '/Failed password/   {print $3" FALLO SSH  "$1" "$2"  "$0}
       /Accepted password/ {print $3" LOGIN SSH  "$1" "$2"  "$0}
       /sudo:/             {print $3" SUDO  esc  "$1" "$2"  "$0}' auth.log
  awk -F'[:[]' '{split($0,a," "); print substr($0,index($0,"[")+13,8)" HTTP  req  "a[1]"  "$0}' access.log
} | sort | awk '{printf "  %s  %-10s\n", $1, $2" "$3}'
