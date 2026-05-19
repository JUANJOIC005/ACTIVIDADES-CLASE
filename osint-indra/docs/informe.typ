#set document(
  title: "Análisis OSINT pasivo de INDRA",
  author: "JUANJOIC005"
)

#set page(
  paper: "a4",
  margin: (x: 2.5cm, y: 2.5cm),
)

#align(center)[
  #text(size: 28pt, weight: "bold")[Análisis OSINT Pasivo]

  #v(0.5cm)

  #text(size: 20pt)[Empresa del IBEX35]

  #v(0.8cm)

  #text(size: 24pt, weight: "bold")[INDRA GROUP]

  #v(1.5cm)

  #line(length: 60%)

  #v(1.5cm)

  #text(size: 14pt)[Práctica 1 — Técnicas de Hacking]

  #v(0.5cm)

  #text(size: 12pt)[Reconocimiento pasivo mediante técnicas OSINT]

  #v(2cm)

  #text(size: 12pt)[
  Autor: Juanjo IC  
  ]

  #v(0.5cm)

  #text(size: 12pt)[
  Universidad Europea
  ]

  #v(0.5cm)

  #text(size: 12pt)[
  2026
  ]
]

#pagebreak()

= Índice

#outline()

#pagebreak()


= Resumen

Este informe presenta un análisis de inteligencia de fuentes abiertas (OSINT) realizado sobre la empresa Indra Group, perteneciente al IBEX35. El objetivo del estudio es identificar información pública relacionada con la presencia digital de la organización mediante técnicas de reconocimiento pasivo. Durante la investigación se analizaron dominios, subdominios, certificados digitales, infraestructura visible, tecnologías web y documentos públicos disponibles en Internet. El análisis se realizó sin interacción directa con los sistemas de la organización, utilizando únicamente fuentes abiertas y herramientas OSINT.

= Investigación de Registros DNS

El Sistema de Nombres de Dominio (DNS) es un componente fundamental de la infraestructura de Internet. Su función principal es traducir nombres de dominio legibles por humanos en direcciones IP que pueden ser utilizadas por los sistemas informáticos.

Durante la fase de reconocimiento pasivo en ciberseguridad, los registros DNS constituyen una de las fuentes de información más valiosas para identificar activos asociados a una organización.

== Tipos de registros DNS

A continuación se describen algunos de los registros DNS más relevantes:

#table(
  columns: (1fr, 3fr),
  stroke: 1pt,

  table.header[Registro][Descripción],

  [A], [Asocia un nombre de dominio con una dirección IPv4.],
  [AAAA], [Similar al registro A, pero para direcciones IPv6.],
  [MX], [Define los servidores de correo electrónico responsables de recibir correos para un dominio.],
  [TXT], [Permite almacenar información textual en el DNS, utilizado frecuentemente para configuraciones de seguridad como SPF, DKIM o verificación de dominios.],
  [CNAME], [Permite que un dominio actúe como alias de otro dominio.],
  [NS], [Indica qué servidores son responsables de gestionar la zona DNS de un dominio.],
  [SOA], [Define información administrativa de la zona DNS, incluyendo el servidor principal y parámetros de actualización.],
  [PTR], [Utilizado en resoluciones inversas para asociar una dirección IP con un nombre de dominio.],
)

== Reconocimiento pasivo vs activo en DNS

Las consultas DNS pueden formar parte tanto del reconocimiento pasivo como del reconocimiento activo dependiendo de cómo se realicen.

El reconocimiento pasivo implica utilizar información ya publicada o accesible públicamente sin interactuar directamente con los sistemas de la organización objetivo. Ejemplos de esto incluyen bases de datos OSINT, motores de búsqueda o registros históricos de DNS.

Por otro lado, el reconocimiento activo implica realizar consultas directas a los servidores DNS del dominio objetivo mediante herramientas como `dig` o `nslookup`. Aunque estas consultas suelen ser legítimas, implican interacción directa con la infraestructura del objetivo, por lo que se consideran técnicas activas dentro del proceso de reconocimiento.

== Modelo de negocio de Indra

Indra Group es una multinacional española del sector tecnológico especializada en consultoría, sistemas de defensa, transporte, energía y transformación digital. La empresa opera a nivel internacional y desarrolla soluciones tecnológicas para sectores estratégicos.

Entre los principales servicios que ofrece destacan:

- Sistemas de defensa y seguridad
- Soluciones para gestión del tráfico aéreo
- Sistemas de transporte inteligente
- Consultoría tecnológica y transformación digital
- Desarrollo de plataformas tecnológicas a través de su filial Minsait

Los principales clientes de Indra incluyen administraciones públicas, organismos gubernamentales, empresas del sector transporte, telecomunicaciones, banca y defensa.

En cuanto a proveedores, la compañía trabaja con múltiples proveedores tecnológicos y plataformas cloud, destacando el uso de servicios de infraestructura como Amazon Web Services (AWS) para el despliegue de parte de su infraestructura digital.


= Introducción

La inteligencia de fuentes abiertas (OSINT, Open Source Intelligence) es una disciplina ampliamente utilizada en ciberseguridad para recopilar y analizar información disponible públicamente sobre una organización. Este tipo de análisis permite comprender la superficie de exposición digital de una entidad y detectar posibles activos accesibles desde Internet.

En el ámbito de la seguridad informática, el reconocimiento pasivo constituye la primera fase de cualquier proceso de análisis o auditoría de seguridad. A través de este enfoque se recopila información pública sin realizar interacción directa con los sistemas objetivo, evitando así alterar su funcionamiento o generar actividad detectable.

En este trabajo se ha realizado un análisis OSINT pasivo sobre la empresa Indra Group, una multinacional española del sector tecnológico y de defensa. El objetivo es identificar información pública sobre su infraestructura digital, tecnologías utilizadas y posibles activos expuestos en Internet.

= Desarrollo

== Metodología

La investigación se llevó a cabo mediante técnicas de reconocimiento pasivo utilizando diferentes herramientas OSINT. En primer lugar, se identificaron los dominios asociados a la organización y se analizó su información WHOIS. Posteriormente se realizó un proceso de enumeración pasiva de subdominios mediante diversas herramientas especializadas.

Además, se analizaron registros de transparencia de certificados digitales, resolución DNS para identificar direcciones IP asociadas y tecnologías web utilizadas por la organización. Finalmente, se buscaron documentos públicos disponibles en el dominio corporativo para analizar posibles metadatos.

Todas las técnicas utilizadas se realizaron exclusivamente mediante fuentes abiertas, sin realizar escaneos activos ni interacción directa con los sistemas de la organización.

#pagebreak()

== Herramientas utilizadas

Durante el análisis se emplearon diversas herramientas de reconocimiento pasivo como Subfinder @subfinder, Amass @amass, DNSX @dnsx, WhatWeb @whatweb, ExifTool @exiftool y theHarvester @harvester. Asimismo, se utilizaron registros de transparencia de certificados mediante la plataforma crt.sh @crtsh.

= Resultados

== Dominio principal

El dominio principal identificado para la organización es:

- indragroup.com

El análisis WHOIS del dominio revela que fue registrado el 28 de julio de 2023 a través del registrador Tucows Domains Inc. Además, los servidores DNS asociados pertenecen al dominio indra.es, lo que indica que la organización gestiona parte de su infraestructura DNS bajo su propio dominio corporativo.

== Huella digital geográfica

El análisis de las direcciones IP asociadas a los subdominios identificados indica que gran parte de la infraestructura web de la organización se encuentra alojada en servicios cloud de Amazon Web Services (AWS).

Las direcciones IP detectadas pertenecen principalmente a rangos asociados a infraestructuras ubicadas en centros de datos de Estados Unidos, lo que es habitual cuando se utilizan servicios globales de CDN como Amazon CloudFront.

El uso de redes de distribución de contenido permite a la organización mejorar el rendimiento y la disponibilidad de sus servicios web a nivel global, además de proporcionar una capa adicional de protección frente a ataques dirigidos contra los servidores de origen.

== Presencia en redes sociales

La organización mantiene presencia activa en diversas plataformas de redes sociales, utilizadas principalmente para comunicación corporativa, difusión de noticias y promoción de servicios tecnológicos.

Entre las principales plataformas identificadas destacan:

- LinkedIn
- Twitter / X
- YouTube
- Instagram

Estas plataformas permiten a la organización difundir información corporativa, comunicar avances tecnológicos y mantener interacción con clientes, socios y profesionales del sector tecnológico.

== Subdominios identificados

Durante el proceso de enumeración pasiva se identificaron diversos subdominios asociados al dominio principal.

#table(
  columns: (1.5fr, 2fr),
  stroke: 1pt,

  table.header[Subdominio][Posible función],

  [airtraffic.indragroup.com], [Sistemas de gestión de tráfico aéreo],
  [defence.indragroup.com], [División de defensa],
  [mobility.indragroup.com], [Soluciones de transporte],
  [quantum.indragroup.com], [Investigación en tecnologías cuánticas],
  [space.indragroup.com], [División aeroespacial],
  [go.info.indragroup.com], [Comunicación y marketing],
  [www.indragroup.com], [Página web principal],
)

La presencia de subdominios asociados a diferentes áreas tecnológicas refleja una infraestructura web segmentada según las distintas líneas de negocio de la empresa.

== Ejemplos de Google Dorking

Durante la investigación OSINT se utilizaron técnicas de búsqueda avanzada conocidas como "Google Dorking". Estas permiten localizar información específica dentro de un dominio mediante operadores avanzados de los motores de búsqueda.

A continuación se presentan algunos ejemplos aplicables al dominio analizado:

#table(
  columns: (1.6fr, 2.4fr),
  stroke: 1pt,

  table.header[Dork][Objetivo],

  [`site:indragroup.com filetype:pdf`], [Identificar documentos públicos publicados en el dominio.],
  [`site:indragroup.com intitle:login`], [Buscar posibles páginas de autenticación asociadas al dominio.],
  [`site:indragroup.com ext:xls OR ext:doc`], [Localizar documentos ofimáticos potencialmente publicados por error.],
)

Este tipo de consultas permite identificar información pública que podría revelar activos adicionales o documentos sensibles expuestos en Internet.
== Certificados digitales

El análisis de los registros de transparencia de certificados mediante la plataforma crt.sh permitió identificar la existencia de certificados wildcard asociados al dominio analizado.

Entre los certificados identificados destacan:

- \*.indragroup.com
- \*.quantum.indragroup.com

El uso de certificados wildcard permite proteger múltiples subdominios bajo un único certificado TLS, lo que sugiere la posible existencia de subdominios adicionales no visibles públicamente.

== Infraestructura e IPs detectadas

Mediante resolución DNS se identificaron diversas direcciones IP asociadas a los subdominios detectados.

#table(
  columns: 2,
  stroke: 1pt,

  table.header[Subdominio][Infraestructura],

  [www.indragroup.com], [AWS],
  [defence.indragroup.com], [AWS CloudFront],
  [mobility.indragroup.com], [AWS CloudFront],
  [airtraffic.indragroup.com], [AWS],
  [space.indragroup.com], [AWS],
  [go.info.indragroup.com], [AWS],
)

Las direcciones IP identificadas pertenecen a rangos asociados a Amazon Web Services (AWS), lo que indica que la organización utiliza infraestructura cloud para el despliegue de sus servicios web. Asimismo, se observó el uso de Amazon CloudFront como red de distribución de contenido (CDN).

== Tecnologías web identificadas

El análisis de la página principal mediante herramientas de fingerprinting web permitió identificar diversas tecnologías utilizadas por la organización.

#table(
  columns: (1fr, 2fr),
  stroke: 1pt,

  table.header[Tecnología][Descripción],

  [HTML5], [Estándar moderno de desarrollo web],
  [Google Tag Manager], [Gestión de analítica y etiquetas],
  [Open Graph Protocol], [Integración con redes sociales],
)

Además, se detectaron cabeceras de seguridad como Strict-Transport-Security, Content-Security-Policy y X-Frame-Options, lo que indica la implementación de diversas medidas de seguridad web.

== Documentos públicos

Mediante técnicas de búsqueda avanzada se identificaron documentos PDF públicos asociados al dominio analizado. El análisis de metadatos realizado con ExifTool no reveló información sensible adicional como autores o software de creación, lo que sugiere una correcta gestión de los metadatos antes de la publicación de documentos.

= Conclusiones

El análisis OSINT realizado permitió identificar diversos activos digitales asociados a la empresa Indra Group mediante técnicas de reconocimiento pasivo. Los resultados muestran que la organización utiliza una infraestructura cloud basada en Amazon Web Services y emplea servicios de CDN como Amazon CloudFront para distribuir su contenido web.

Asimismo, se observó una estructura de subdominios alineada con las distintas áreas tecnológicas de la empresa, lo que refleja una organización segmentada de sus servicios digitales. El análisis también mostró la implementación de diversas medidas de seguridad web y una correcta gestión de metadatos en documentos públicos.

Este tipo de análisis demuestra cómo la información disponible públicamente puede proporcionar una visión general de la infraestructura digital de una organización, lo que resalta la importancia de gestionar adecuadamente la exposición de activos en Internet.

= Bibliografía

#bibliography("referencias.bib")
