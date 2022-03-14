# WAF-NGINX
Configuración simple de WAF para servir sitios web y API's

## Contenidos

- 1 Firewall de Aplicaciones Web - WAF
    - 1.1 Introducción y objetivos
    - 1.2 Generalidades de un firewall de aplicaciones web
- 2 Propuesta
    - 2.1 Requerimientos e implementación

## Introducción y objetivos

Existe la necesidad de proveer de seguridad a aplicaciones web legadas las cuales no pueden ser actualizadas por motivos técnicos. Ante la imposibilidad de realizar cambios en el servidor de la aplicación y no poder realizar un desarrollo posterior sobre la misma, la propuesta es implementar un **WAF**.

Un firewall de aplicaciones web (WAF) es un tipo de firewall que supervisa, filtra o bloquea el tráfico HTTP hacia y desde una aplicación web. Al inspeccionar el tráfico HTTP un WAF protege a las aplicaciones web contra ataques como los de inyección SQL, XSS y falsificación de petición de sitios cruzados (CSRF).

### Generalidades de un firewall de aplicaciones web

El firewall de aplicaciones web (WAF) ofrece una protección centralizada a las aplicaciones web contra vulnerabilidades de seguridad comunes. Las aplicaciones web son cada vez más el objetivo de ataques malintencionados que aprovechan vulnerabilidades habitualmente conocidas. Los scripts entre sitios y las inyecciones de código SQL están dentro de los ataques más comunes.

El firewall de aplicaciones web se basa en un conjunto de reglas básicas, las cuales pueden ser variadas como OWASP ModSecurity Core Rule Set y complementarse por medio de CrowdSec.

El modo de operación del WAF, es envolver la aplicación web y redirigir los pedidos sanitizados hacia ella.

![Modo de operación WAF](images/WAF.jpg)


## Propuesta

Se propone utilizar el software Nginx, es de código abierto y utilizado en sistemas linux como servidor web o como proxy reverso para reenviar mensajes de registro en una red. Apoyándose en **modSecurity** y **CrowdSec**.

modSecurity™ es un firewall de aplicaciones Web embebible que ejecuta como módulo del servidor web, provee protección contra diversos ataques hacia aplicaciones Web y permite monitorizar tráfico HTTP, así como realizar análisis en tiempo real sin necesidad de hacer cambios a la infraestructura existente.

CrowdSec es un IPS colaborativo y de código abierto. Analice comportamientos, responda a ataques y recibe señales de detección de fuentes cloud comunitarias.

modSecurity se integra en Nginx para que este pueda tomar las determinaciones necesarias.

Por otro lado CrowdSec corre por fuera de Nginx, sirviendo de apoyo.

- CrowdSec se instalará con opciones básicas de análisis de eventos, en primera instancia como monitoreo y luego se implementarán bloqueos.
- ModSecurity se instalará con las configuraciones de OWASP ModSecurity Core Rule Set.

### Requerimientos e implementación

Dependiendo del tráfico del sitio web, los requerimientos pueden variar, así que hay que determinar los requisitos normales de un proxy reverso con NGINX y sus módulos necesarios para luego sumarles los requisitos de procesamientos de solicitudes de tráfico HTTP/HTTPS por medio de  **modSecurity** y **CrowdSec**.

Se debe determinar y testear 
- Utilización de certificados SSL 
- Casos de prueba de las aplicaciones afectadas en cuestión
   - Correr aplicaciones de testeo de seguridad com OpenVAS, Nikto, Nmap+NSE,wpscan etc
- Dimensionamiento de recursos en base a las estadisticas de utilización del servidor

### Referencias relacionadas

## Proyectos

- https://crowdsec.net/
- https://github.com/SpiderLabs/ModSecurity-nginx
- https://github.com/coreruleset/coreruleset
- https://www.tecmint.com/install-modsecurity-nginx-debian-ubuntu/

## Reportes

- https://github.com/molu8bits/modsecurity-parser
- https://app.crowdsec.net/

