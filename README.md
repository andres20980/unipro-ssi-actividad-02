# Laboratorio de la actividad 2 (SSI)

Entorno reproducible usado para generar las capturas de la memoria. Todo se ejecuta
en contenedores locales; no se lanza nada contra sistemas de terceros. Los logs de
`logs/` son **datos simulados** creados para el ejercicio (incidente del 15-may 03:14).

## Requisitos
- Docker. Imágenes usadas: `jasonish/suricata:7.0` y `php:8.3-cli`; los scripts de
  `capturas/` usan además `alpine:3.20`, `nicolaka/netshoot`, `instrumentisto/nmap` y
  `python:3.12-alpine`.

## Contenido y cómo reproducir

### Parte I — IDS (Suricata)
Reglas en `suricata/local.rules`. Validación de la sintaxis y carga:
```
docker run --rm --entrypoint sh -v "$PWD/suricata":/lab jasonish/suricata:7.0 \
  -c 'suricata -T -c /etc/suricata/suricata.yaml -S /lab/local.rules \
      --set "vars.address-groups.HOME_NET=[10.10.0.0/16]" -v'
```
Detección real de un escaneo: `capturas/01_scan_ids.sh` crea una red Docker **interna**
(sin salida a Internet) con un contenedor atacante y uno objetivo, lanza un escaneo SYN
real con nmap (`-sS`) mientras tcpdump captura el tráfico, y analiza el pcap con Suricata
y las reglas locales (`suricata -r`). Produce las alertas `LOCAL SCAN` de `fast.log`.
```
./capturas/01_scan_ids.sh
```

### Parte II — Código de login
- `login/vulnerable_demo.php`: reproduce el fragmento inseguro del enunciado y muestra
  el bypass por inyección SQL sobre una base de datos SQLite en memoria.
- `login/auth.php` + `login/login.php`: versión reescrita (D3) con PDO parametrizado,
  Argon2id, límite de intentos, CSRF y sesión endurecida.
- `login/pruebas.php`: batería de pruebas de la versión segura.
```
docker run --rm -v "$PWD/login":/app -w /app php:8.3-cli php vulnerable_demo.php
docker run --rm -v "$PWD/login":/app -w /app php:8.3-cli php pruebas.php
```

### Parte III — Forense
`logs/analisis.sh` correlaciona `auth.log` y `access.log` con grep/awk/join y
construye la línea temporal del incidente.
```
./logs/analisis.sh
```

### Parte IV — Sniffing
`capturas/02_sniffing.sh` crea una red Docker **interna**, envía un login por HTTP sin
cifrar (credenciales ficticias de laboratorio) entre dos contenedores y lo captura con
tcpdump, mostrando usuario y contraseña en claro.
```
./capturas/02_sniffing.sh
```

Las imágenes resultantes están en `img/`. Los `.pcap` generados por los scripts se
escriben en `pcap/` (no versionado).
