#set document(title: "P3 - MITM y suplantación", author: "Juan José Leganés")
#set text(font: "Arial", size: 11pt, lang: "es")
#set page(
  paper: "a4",
  margin: (x: 2.2cm, y: 2.1cm),
  numbering: "1",
)
#show heading: it => [
  #set block(above: 1.15em, below: 0.55em)
  #it
]
#show table.cell.where(y: 0): set text(weight: "bold")

#align(center)[
  #text(size: 20pt, weight: "bold")[P3 - MITM y suplantación]

  #v(0.5cm)
  #text(size: 13pt)[Práctica de seguridad en redes]

  #v(0.3cm)
  #text(size: 10pt)[Entorno controlado de laboratorio]
]

#v(0.7cm)

= Resumen

Esta práctica estudia cómo una persona situada dentro de una red local podría hacerse pasar por la puerta de enlace para observar el tráfico que envía otro equipo. El objetivo no es atacar una red real, sino entender por qué una configuración aparentemente normal puede fallar si los equipos aceptan respuestas ARP falsas. Los hallazgos se han contextualizado en un laboratorio aislado, con direcciones privadas y datos de prueba, para extraer medidas de defensa aplicables a una red doméstica, docente o corporativa.

El resultado principal es que la suplantación ARP puede redirigir el tráfico sin que el usuario pierda conectividad. Sin embargo, el cifrado TLS limita el acceso al contenido sensible cuando los certificados se validan correctamente. Por tanto, el riesgo más relevante no es solo la captura directa de contraseñas, sino la posibilidad de observar metadatos, degradar servicios inseguros, manipular tráfico no cifrado y preparar ataques posteriores.

#pagebreak()

#outline(title: "Índice", depth: 3)

#pagebreak()

= Introduccion

ARP es el protocolo usado en redes IPv4 locales para relacionar una dirección IP con una dirección MAC. Su diseño original no incorpora autenticación de las respuestas, por lo que un host puede aceptar asociaciones falsas si recibe paquetes ARP convincentes @rfc826. Esta debilidad permite ataques de suplantación en capa 2: el atacante anuncia que su MAC corresponde a una IP relevante, normalmente la puerta de enlace, y logra colocarse entre la víctima y el resto de la red.

Un ataque Man-in-the-Middle (MITM) consiste en interceptar una comunicación haciendo que las partes sigan creyendo que hablan directamente entre sí @owaspMitm. En esta práctica se analiza una variante local basada en ARP spoofing. La documentación de herramientas como bettercap describe este tipo de módulo como un mecanismo que envía paquetes ARP manipulados para redirigir tráfico de hosts seleccionados @bettercapArpSpoof, y lo presenta dentro de una familia más amplia de técnicas MITM @bettercapMitmIntro.

El trabajo se limita a un laboratorio autorizado. No se ejecutan acciones contra redes de terceros ni se capturan datos personales. Las evidencias se expresan con IP y MAC privadas de ejemplo para que la lectura técnica sea clara sin exponer información real.

= Desarrollo

== Entorno de laboratorio

La práctica se contextualiza en una red aislada `192.168.56.0/24`, equivalente a una red host-only o interna de virtualización. Los roles son:

#table(
  columns: (1.2fr, 1.2fr, 1.3fr, 2fr),
  inset: 6pt,
  stroke: 0.5pt,
  align: left,
  table.header([Rol], [IP], [MAC], [Funcion]),
  [Víctima], [`192.168.56.23`], [`08:00:27:10:20:23`], [Equipo que genera tráfico normal de usuario.],
  [Gateway], [`192.168.56.1`], [`08:00:27:aa:bb:01`], [Puerta de enlace legítima de la red.],
  [Auditor], [`192.168.56.66`], [`08:00:27:de:ad:03`], [Equipo usado para observar y documentar el efecto de la suplantación.],
)

#figure(
  image("images/topologia_laboratorio.png", width: 100%),
  caption: [Topología usada para contextualizar la prueba.]
)

== Metodologia

La metodología se dividió en cinco fases. Primero se tomó una línea base de la caché ARP para confirmar que la víctima resolvía correctamente la MAC de la puerta de enlace. Después se documentó la fase de suplantación, donde la IP del gateway quedó asociada a la MAC del auditor. A continuación se verificó que el tráfico seguía circulando, lo cual es importante porque un MITM efectivo intenta pasar desapercibido. Posteriormente se comparó el comportamiento de tráfico HTTP y HTTPS. Por último se restauró la asociación ARP legítima.

Las herramientas citadas para esta práctica son Wireshark, por su capacidad de filtrar y revisar paquetes capturados @wiresharkUserGuide; bettercap, como referencia técnica de módulos de suplantación ARP @bettercapArpSpoof; y `uv` con Python para generar evidencias auxiliares reproducibles en la carpeta `src`.

== Criterios de evaluación técnica

Se consideraron tres criterios:

- Cambio de caché ARP: si la IP del gateway aparece vinculada a una MAC distinta de la esperada.
- Continuidad de servicio: si la víctima mantiene conectividad durante la redirección.
- Exposición de información: si el tráfico visible permite recuperar contenido, metadatos o solo patrones de conexión.

Estos criterios permiten diferenciar entre una interrupción de red y un MITM funcional. Una pérdida de conectividad sería visible para el usuario y tendría valor limitado para interceptar información; en cambio, una redirección con reenvío mantiene la sesión activa y aumenta el riesgo.

= Resultados
== Servicios activos

#figure(
  image("images/Captura de pantalla 2026-05-18 235214.png", width: 100%),
  caption: [Estado de los contenedores Docker utilizados en el laboratorio.]
)

La captura anterior muestra todos los servicios activos correctamente desplegados mediante Docker Compose.

== Configuración de la red DNS

#figure(
  image("images/Captura de pantalla 2026-05-18 235356.png", width: 95%),
  caption: [Inspección de la red virtual DNS mediante Docker.]
)

Se observa la configuración de la red `10.10.30.0/24`, utilizada para el escenario DNS.

= Parte 1 — Detección de ARP Spoofing

== Fundamentos teóricos

El protocolo ARP (Address Resolution Protocol) permite asociar direcciones IP con direcciones MAC dentro de redes locales Ethernet. Debido a que ARP carece de mecanismos de autenticación, un atacante puede enviar respuestas ARP falsas modificando las tablas ARP de otros equipos.

Esta técnica se conoce como ARP Spoofing o ARP Poisoning y permite:

- Interceptar tráfico.
- Realizar ataques MITM.
- Redirigir comunicaciones.
- Capturar credenciales.

== Verificación de conectividad

#figure(
  image("images/Captura de pantalla 2026-05-18 235425.png", width: 90%),
  caption: [Comprobación de conectividad entre la víctima y el router.]
)

Se verifica la resolución ARP correcta antes del ataque.

== Implementación del IDS ARP

Se desarrolló la función `alert_arpspoof.py` utilizando Scapy para monitorizar respuestas ARP en tiempo real.

La lógica implementada realiza:

- Monitorización de paquetes ARP.
- Asociación IP ↔ MAC legítima.
- Detección de cambios inesperados.
- Generación de alertas en consola.

== Monitorización activa

#figure(
  image("images/Captura de pantalla 2026-05-18 235446.png", width: 85%),
  caption: [Sistema IDS monitorizando tráfico ARP.]
)

== Generación del ataque

El tráfico malicioso se genera mediante el script `generate_arp_spoof.py`.

#figure(
  image("images/Captura de pantalla 2026-05-18 235851.png", width: 92%),
  caption: [Generación de tráfico ARP falso desde el atacante.]
)

El atacante envía respuestas ARP manipuladas intentando asociar la IP del router con la MAC del atacante.

== Resultado de la detección

#figure(
  image("images/Captura de pantalla 2026-05-18 235858.png", width: 92%),
  caption: [Monitorización de respuestas ARP y validación del comportamiento.]
)

El sistema IDS es capaz de detectar cambios de asociación IP/MAC y monitorizar anomalías en tiempo real.

== Validación de acceso al servidor web

#figure(
  image("images/Captura de pantalla 2026-05-18 235952.png", width: 90%),
  caption: [Conectividad hacia el servidor web desde la víctima.]
)

== Captura de tráfico ARP

#figure(
  image("images/Captura de pantalla 2026-05-19 000000.png", width: 100%),
  caption: [Captura de tráfico ARP mediante tcpdump.]
)

La captura evidencia el intercambio ARP dentro de la red local y permite validar el comportamiento del protocolo.

== Uso de Bettercap

Bettercap fue utilizado para automatizar el proceso de envenenamiento ARP.

#figure(
  image("images/Captura de pantalla 2026-05-19 000021.png", width: 100%),
  caption: [Configuración y ejecución de Bettercap.]
)

== Evidencia del cambio ARP

#figure(
  image("images/Captura de pantalla 2026-05-19 000114.png", width: 80%),
  caption: [Visualización de la tabla ARP alterada.]
)

La víctima termina asociando la dirección IP del router con la MAC del atacante, demostrando el éxito del ataque MITM.

= Parte 2 — DNS Snooping y Suplantación DNS

== Fundamentos teóricos

Los ataques relacionados con DNS permiten obtener información sobre la infraestructura interna o manipular respuestas DNS.

El ataque de Kaminsky explota la predictibilidad de ciertas consultas DNS para introducir registros falsos en caché. Además, el envío masivo de consultas hacia subdominios inexistentes permite:

- Enumerar infraestructura.
- Analizar comportamiento DNS.
- Detectar resolutores vulnerables.
- Saturar mecanismos de caché.

== Configuración del cliente DNS

#figure(
  image("images/Captura de pantalla 2026-05-28 032122.png", width: 95%),
  caption: [Configuración DNS del cliente y resolución de nombres.]
)

La resolución DNS se realiza correctamente a través del resolver `10.10.30.53`.

== Generación de tráfico DNS malicioso

#figure(
  image("images/Captura de pantalla 2026-05-28 032226.png", width: 92%),
  caption: [Generación automatizada de consultas DNS sospechosas.]
)

El script genera consultas hacia subdominios aleatorios inexistentes dentro del dominio `lab.local`.

== Captura del tráfico DNS

#figure(
  image("images/Captura de pantalla 2026-05-28 032632.png", width: 100%),
  caption: [Captura de tráfico DNS mediante tcpdump.]
)

Se observan múltiples respuestas `NXDOMAIN`, patrón típico asociado a ataques de DNS Snooping o intentos de reconocimiento.

== Implementación del IDS DNS

La función `alert_dnssnooping.py` implementa un mecanismo de detección basado en umbrales.

El IDS analiza:

- Número de consultas DNS.
- Frecuencia temporal.
- Existencia del subdominio.
- Respuestas NXDOMAIN.

Cuando el volumen de consultas supera el umbral definido, el sistema genera una alerta indicando actividad potencialmente maliciosa.

= Análisis técnico

== ARP Spoofing

La práctica demuestra que ARP es un protocolo inherentemente inseguro debido a la ausencia de autenticación. Un atacante conectado al mismo segmento Ethernet puede manipular fácilmente las tablas ARP.

La detección basada en monitorización de asociaciones IP/MAC resulta efectiva para identificar anomalías en redes locales.

== DNS Snooping

Las ráfagas de consultas DNS hacia dominios inexistentes constituyen un patrón característico de reconocimiento y fingerprinting.

El uso de umbrales permite detectar actividades anómalas minimizando falsos positivos.

== Hallazgos contextualizados

#table(
  columns: (1.15fr, 1.35fr, 2fr, 2.2fr, 0.9fr),
  inset: 5pt,
  stroke: 0.5pt,
  align: left,
  table.header([Fase], [Indicador], [Evidencia], [Interpretacion], [Riesgo]),
  [Línea base], [ARP normal], [Gateway asociado a su MAC legítima.], [La red funciona de forma esperada y no hay indicios de intermediación.], [Bajo],
  [Suplantación], [Duplicidad IP/MAC], [La IP del gateway pasa a la MAC del auditor.], [La víctima acepta una asociación falsa por falta de autenticación en ARP.], [Alto],
  [Intercepción], [Tráfico reenviado], [ICMP y HTTP continúan funcionando.], [La víctima no percibe la redirección, lo que aumenta el riesgo operativo.], [Alto],
  [HTTPS], [Contenido cifrado], [TLS protege el cuerpo de la comunicación.], [El atacante ve metadatos, pero no contenido sensible si se validan certificados.], [Medio],
  [Restauración], [ARP legítimo], [La caché vuelve al gateway real.], [La limpieza posterior reduce impacto residual y confirma la causa del desvío.], [Bajo],
)

== Lectura de impacto

El impacto depende del tipo de tráfico. En HTTP sin cifrado, el intermediario puede observar rutas, cabeceras y contenido de prueba. En HTTPS correctamente validado, el contenido viaja cifrado y la utilidad de la posición MITM se reduce a metadatos como direcciones, tiempos, volumen de tráfico y nombres de servidor cuando sean visibles. Esta diferencia justifica mantener HTTPS, HSTS y validación estricta de certificados incluso dentro de redes internas.

También se observó que la conectividad por sí sola no demuestra seguridad. La víctima puede navegar o hacer ping mientras su tráfico pasa por un equipo no autorizado. Por eso, las defensas deben mirar señales de capa 2, no solo disponibilidad de servicios.

== Medidas de mitigacion

#table(
  columns: (1.5fr, 2.4fr, 2.1fr),
  inset: 6pt,
  stroke: 0.5pt,
  align: left,
  table.header([Medida], [Como reduce el riesgo], [Contexto recomendado]),
  [Dynamic ARP Inspection], [Valida respuestas ARP contra información fiable de DHCP snooping.], [Switches gestionables en redes corporativas o docentes.],
  [Segmentación], [Limita que un equipo de usuario pueda observar tráfico de otros segmentos.], [Aulas, laboratorios y redes con BYOD.],
  [HTTPS y HSTS], [Impide leer o modificar contenido aunque exista intermediacion de red.], [Servicios web internos y externos.],
  [Monitorización ARP], [Detecta cambios anormales de MAC para IP críticas.], [Gateway, servidores y subredes sensibles.],
  [Control de acceso a red], [Evita que dispositivos no autorizados entren en la LAN.], [Wi-Fi empresarial, cableado compartido y laboratorios.],
)

= Conclusiones

La práctica muestra que ARP es un punto débil relevante en redes locales porque confía en mensajes no autenticados. Un atacante situado en la misma LAN puede provocar que una víctima envíe tráfico a una MAC que no corresponde al gateway real. El hallazgo más importante es que la conectividad puede mantenerse durante la redirección, de modo que el usuario no siempre detecta el ataque por síntomas visibles.

El riesgo no debe simplificarse como "captura de contraseñas". En redes modernas, TLS reduce mucho esa posibilidad cuando se usa bien. Aun así, el MITM conserva valor ofensivo porque permite observar metadatos, identificar servicios, manipular tráfico no cifrado y degradar protocolos mal configurados. Por ello, la defensa debe combinar medidas de capa 2, cifrado extremo a extremo y monitorización.

En una red real, la recomendación prioritaria sería activar protecciones de switch como DHCP snooping y Dynamic ARP Inspection, separar redes de usuarios y servidores, y auditar periódicamente cambios de caché ARP en activos críticos. Estas medidas transforman un ataque sencillo de ejecutar en laboratorio en una actividad más visible y difícil de sostener.

= Bibliografía

#bibliography("bibliography.bib", title: none)
