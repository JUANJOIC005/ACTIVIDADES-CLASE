# P3 - MITM y suplantacion

Entrega de la practica P3 sobre deteccion de ARP Spoofing y DNS Snooping/Kaminsky en un entorno Docker local.

## Archivos principales

```text
P3_Mitm_y_suplantacion/
├── docker-compose.yml
├── docker/
│   ├── Dockerfile.attacker
│   └── Dockerfile.lab
├── src/
│   ├── alert_arpspoof.py
│   ├── alert_dnssnooping.py
│   ├── bettercap_arp_spoof.cap
│   ├── dns_resolver.py
│   ├── dns_server.py
│   ├── generate_arp_spoof.py
│   ├── generate_dns_snooping.py
│   └── generate_evidence.py
├── doc/
│   ├── bibliography.bib
│   ├── images/
│   └── report.typ
├── EVIDENCIAS.md
└── P3.pdf
```

## Ejecutar laboratorio

Desde la raiz del proyecto:

```powershell
docker compose up -d --build
```

Sigue la guia de capturas en `EVIDENCIAS.md`.

Para parar y limpiar los contenedores:

```powershell
docker compose down
```

## Reproducir imagenes auxiliares

```powershell
uv run --directory src python generate_evidence.py
```

El script genera las imagenes y el CSV usados como apoyo documental en `doc/images/`.

## Compilar el informe

```powershell
typst compile doc/report.typ doc/report.pdf
```
