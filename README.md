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
