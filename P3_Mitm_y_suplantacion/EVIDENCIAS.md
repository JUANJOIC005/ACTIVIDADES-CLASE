# Guia rapida de capturas para P3

Ejecuta todo desde la raiz del proyecto:

```powershell
docker compose up -d --build
```

Cuando termines:

```powershell
docker compose down
```

## Capturas generales

1. Contenedores levantados:

```powershell
docker compose ps
```

2. Redes creadas:

```powershell
docker network ls
```

3. Inspeccion de red ARP. Busca el nombre que termine en `mitm_lan`:

```powershell
docker network inspect <red_mitm_lan>
```

4. Inspeccion de red DNS. Busca el nombre que termine en `dns_lan`:

```powershell
docker network inspect <red_dns_lan>
```

## Parte 1 - ARP Spoofing

Abre tres terminales.

### Terminal 1: linea base ARP de la victima

```powershell
docker exec -it p3_arp_victim ping -c 2 10.10.10.1
docker exec -it p3_arp_victim ip neigh
```

Haz captura: debe verse la asociacion normal entre `10.10.10.1` y una MAC.

### Terminal 2: IDS ARP

```powershell
docker exec -it p3_arp_victim python /lab/src/alert_arpspoof.py --iface eth0 --watch 10.10.10.1
```

Haz captura: debe verse el IDS esperando paquetes ARP.

### Terminal 3: ataque con bettercap

```powershell
docker exec -it p3_attacker bettercap -iface eth0 -caplet /lab/src/bettercap_arp_spoof.cap
```

Haz captura de bettercap en ejecucion.

Vuelve a la terminal del IDS y haz captura cuando aparezca:

```text
ALERTA ARP SPOOFING
```

### Alternativa de validacion Scapy

Si bettercap no arranca en tu equipo, usa este generador para producir la evidencia de la alerta IDS:

```powershell
docker exec -it p3_attacker python3 /lab/src/generate_arp_spoof.py --victim 10.10.10.10 --gateway 10.10.10.1 --count 10
```

Esta alternativa sirve para demostrar que la firma `alert_arpspoof` detecta respuestas ARP falsas.

### Captura de trafico ARP

En otra terminal:

```powershell
docker exec -it p3_arp_victim tcpdump -nne -i eth0 arp
```

Repite el ataque y haz captura del paquete ARP sospechoso.

### Conectividad durante la prueba

```powershell
docker exec -it p3_arp_victim ping -c 2 10.10.20.20
docker exec -it p3_arp_victim curl http://10.10.20.20
```

Haz captura para justificar el flujo de trafico entre victima, router y servidor web.

## Parte 2 - DNS Snooping

Abre tres terminales.

### Terminal 1: comprobar resolver interno

```powershell
docker exec -it p3_dns_client cat /etc/resolv.conf
docker exec -it p3_dns_client dig @10.10.30.53 www.lab.local
```

Haz captura: debe verse que se usa `10.10.30.53`, no un resolver publico.

### Terminal 2: IDS DNS

```powershell
docker exec -it p3_dns_resolver python /lab/src/alert_dnssnooping.py --iface eth0 --zone lab.local --threshold 8 --window 10 --client 10.10.30.10
```

Haz captura del IDS esperando trafico DNS.

### Terminal 3: generador Scapy

```powershell
docker exec -it p3_dns_client python /lab/src/generate_dns_snooping.py --resolver 10.10.30.53 --zone lab.local --count 20 --delay 0.2
```

Haz captura del generador enviando subdominios falsos.

Vuelve a la terminal del IDS DNS y captura la alerta:

```text
ALERTA DNS SNOOPING
```

### Captura de trafico DNS

```powershell
docker exec -it p3_dns_resolver tcpdump -nne -i eth0 udp port 53
```

Repite el generador Scapy y haz captura de las consultas DNS hacia el resolver local.

## Capturas de codigo que pide la rubrica

Captura estos archivos abiertos en el editor:

- `src/alert_arpspoof.py`: funcion `alert_arpspoof`.
- `src/alert_dnssnooping.py`: funcion `alert_dnssnooping` y umbral.
- `src/generate_dns_snooping.py`: script Scapy generador de trafico.
- `docker-compose.yml`: topologias ARP y DNS.

## Evidencias ya existentes

Estas imagenes ya estaban generadas como apoyo documental:

- `doc/images/topologia_laboratorio.png`
- `doc/images/comparacion_cache_arp.png`
- `doc/images/observaciones.csv`
