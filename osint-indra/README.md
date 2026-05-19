# Práctica 1 — Recogida de Información Pasiva (OSINT)

Repositorio correspondiente a la **Práctica 1 de la asignatura Técnicas de Hacking**.  
El objetivo del trabajo es realizar una investigación de **reconocimiento pasivo (OSINT)** sobre una empresa del **IBEX35**, utilizando únicamente fuentes abiertas.

---

# Empresa analizada

**Indra Group**

Indra es una multinacional española del sector tecnológico especializada en:

- Sistemas de defensa y seguridad
- Gestión de tráfico aéreo
- Transporte inteligente
- Consultoría tecnológica
- Transformación digital a través de **Minsait**

---

# Objetivos de la práctica

- Aplicar técnicas de **reconocimiento pasivo**
- Analizar la **presencia digital de una empresa**
- Identificar **infraestructura, tecnologías y activos expuestos**
- Documentar hallazgos utilizando **metodología OSINT**

---

# Metodología

El análisis se realizó **exclusivamente mediante técnicas de reconocimiento pasivo**, sin interactuar directamente con los sistemas de la organización.

Se investigaron los siguientes aspectos:

- Dominios y registros DNS
- Subdominios públicos
- Certificados digitales
- Infraestructura e IPs
- Tecnologías web
- Documentos públicos
- Huella digital geográfica
- Presencia en redes sociales
- Google Dorking

---

#  Herramientas utilizadas

Durante la investigación se utilizaron diversas herramientas OSINT:

| Herramienta | Uso |
|---|---|
| **Subfinder** | Enumeración pasiva de subdominios |
| **Amass** | Reconocimiento y descubrimiento de activos |
| **DNSX** | Resolución DNS |
| **WhatWeb** | Identificación de tecnologías web |
| **ExifTool** | Análisis de metadatos en documentos |
| **theHarvester** | Búsqueda de información OSINT |
| **crt.sh** | Consulta de certificados TLS |

---

# Hallazgos principales

Durante la investigación se identificaron:

### Subdominios

- `airtraffic.indragroup.com`
- `defence.indragroup.com`
- `mobility.indragroup.com`
- `quantum.indragroup.com`
- `space.indragroup.com`
- `go.info.indragroup.com`
- `www.indragroup.com`

### Infraestructura

- **Amazon Web Services (AWS)**
- **Amazon CloudFront (CDN)**

### Tecnologías detectadas

- HTML5
- Google Tag Manager
- Open Graph Protocol
- Cabeceras de seguridad (HSTS, CSP, X-Frame-Options)

---

#  Estructura del repositorio

```
osint-indra
├── docs
│   ├── informe.typ
│   ├── referencias.bib
│   └── images
│
├── data
│   ├── raw
│   └── processed
│
├── P1_Reconocimiento_pasivo
│   ├── src
│   └── results
│
├── pyproject.toml
└── README.md
```


---

# Consideraciones éticas

Toda la investigación se ha realizado siguiendo **principios de OSINT pasivo**, utilizando únicamente información pública disponible en Internet.

No se realizaron:

- escaneos de puertos
- ataques
- enumeración activa
- interacción directa con sistemas de la organización

---

# Bibliografía

Las herramientas y fuentes utilizadas se encuentran citadas en:


docs/referencias.bib


---

#  Autor

**JUANJOIC005**

Asignatura: **Técnicas de Hacking**  
Universidad Europea  
Año académico **2026**