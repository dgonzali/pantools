#!/usr/bin/env python3
"""
05_pan_policy_test.py
---------------------
Simula que regla de seguridad de Panorama aplicaria primero a un flujo de
trafico dado, siguiendo el orden real de evaluacion de PAN-OS:

  shared pre -> padres pre (raiz->hoja) -> DG pre
               -> DG post -> padres post (hoja->raiz) -> shared post

La jerarquia de Device Groups se infiere de un mapa estatico (STATIC_DG_PARENT_MAP)
que debe mantenerse actualizado con la estructura real de Panorama.

========================================================================
USO
========================================================================

  python 05_pan_policy_test.py --device-group US --src-ip 10.1.1.1 --dst-ip 8.8.8.8 --dst-port udp/53
  python 05_pan_policy_test.py --device-group US --src-zone trust --dst-zone untrust --app ssl
  python 05_pan_policy_test.py --device-group US --src-ip 10.0.0.1 --dst-ip 1.1.1.1 --dst-port tcp/443 --url google.com
  python 05_pan_policy_test.py --device-group US --src-ip 10.0.0.1 --dst-ip 1.1.1.1 --dst-port tcp/443 --app ssl --ignore-app

========================================================================
ARGUMENTOS
========================================================================

Obligatorio:
  --device-group DG     Device Group objetivo (y sus ancestros hasta shared)

Filtros de trafico (todos opcionales; los no indicados se tratan como "any"):
  --src-ip  IP          IP de origen
  --dst-ip  IP          IP de destino
  --src-port PUERTO     Puerto origen:  numero, tcp/num o udp/num
  --dst-port PUERTO     Puerto destino: numero, tcp/num o udp/num
  --src-zone ZONA       Zona de origen
  --dst-zone ZONA       Zona de destino
  --app  APP            Nombre de aplicacion PAN-OS (ej: ssl, dns, openai)
  --ignore-app          Ignora el campo application al evaluar reglas
  --url  URL            URL o dominio a comparar contra el campo url-category
                        de las reglas (ej: google.com, https://malware.example.com)

Opciones adicionales:
  --output FICHERO      Guarda el resultado tambien en un fichero de texto
  --debug               Escribe traza detallada en debug.txt
  --debug-stdout        Ademas de debug.txt, muestra las trazas por consola

========================================================================
LOGICA DE EVALUACION DE PUERTOS Y SERVICIOS
========================================================================

El script maneja cuatro tipos de campo 'service' en las reglas:

1. service = any
   -> El puerto no se filtra. Se verifica solo compatibilidad de protocolo con
      la aplicacion (ej: ICMP no hara match en una regla con app=dns).

2. service = <objeto concreto>  (ej: service-https, tcp-8080, mi-servicio)
   -> Se resuelve el objeto contra los objetos de servicio descargados de
      Panorama (shared + ancestros + DG). Los servicios predefinidos de PAN-OS
      'service-http' (tcp/80) y 'service-https' (tcp/443) se incluyen siempre
      aunque no aparezcan en la config XML.

3. service = application-default  CON  app especifica (no "any")
   -> El firewall usa los puertos por defecto del App-ID de la aplicacion.
      El script verifica que (proto, puerto) coincida con los puertos por defecto
      conocidos de esa app (definidos en _APP_DEFAULT).

      IMPORTANTE: si el usuario NO especifica --app, el script NO podra predecir
      que clasificara el App-ID y DESCARTARA estas reglas para evitar falsos
      positivos. Si el usuario especifica --app, se comprueba proto+puerto contra
      los defaults de esa app. Si usa --ignore-app, se trata como permisivo.

      Ejemplo:
        Regla: app=openai / service=application-default
        --dst-port tcp/443                  -> NO match (no se sabe que detectara App-ID)
        --dst-port tcp/443 --app openai     -> MATCH  (443 esta en defaults de openai)
        --dst-port tcp/8080 --app openai    -> NO match (8080 no es puerto default de openai)
        --dst-port tcp/443 --ignore-app     -> MATCH  (app ignorada, permisivo)

4. service = application-default  CON  app = any
   -> Se trata como permisivo (cualquier puerto puede hacer match).

========================================================================
LOGICA DE URL CATEGORY
========================================================================

Si se especifica --url:
  - Se extrae el hostname/dominio de la URL indicada.
  - Para cada regla evaluada, se lee el campo 'url-category' (tag XML: <category>).
  - Si la regla no tiene url-category o es 'any': pasa sin restriccion.
  - Si la regla tiene una Custom URL Category (definida en Panorama config):
      Se comprueba si el dominio coincide con alguna entrada de esa categoria.
      Patrones soportados:
        google.com      -> coincide con google.com y cualquier subdominio
        *.google.com    -> solo subdominios de google.com
        .google.com     -> equivalente a *.google.com (notacion PAN-OS)
        google.com/ruta -> solo se compara la parte host
  - Si la regla tiene una categoria predefinida de PAN-OS (ej: social-networking):
      No se puede resolver sin acceso a PAN-DB. Se trata como coincidencia
      posible y se indica en el debug.

NOTA: el tag XML del campo URL Category en las reglas de seguridad es <category>,
NO <url-category>. El tag <url-category> se usa en los perfiles de URL Filtering.

========================================================================
MAPEO DE JERARQUIA DE DEVICE GROUPS
========================================================================

El script usa STATIC_DG_PARENT_MAP para determinar la cadena de ancestros
de un Device Group. Este mapa debe actualizarse manualmente cuando se modifique
la jerarquia de Device Groups en Panorama.

Ejemplo de estructura:
  Shared
    America
      US
      LATAM
    Europe
      UK

Representacion en el mapa:
  STATIC_DG_PARENT_MAP = {
      "US":    "America",
      "LATAM": "America",
      "UK":    "Europe",
      # Los DGs raiz (America, Europe) no aparecen: su padre es implicitamente shared
  }
"""

import argparse
import ipaddress
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urlparse

import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

PAN_URL     = os.getenv("PAN_URL", "").rstrip("/")
PAN_API_KEY = os.getenv("PAN_API_KEY", "")

if not PAN_URL or not PAN_API_KEY:
    sys.exit("[ERROR] PAN_URL y PAN_API_KEY deben estar definidas en el fichero .env")

TIMEOUT = 30

# ---------------------------------------------------------------------------
# Jerarquía estática de Device Groups
# ---------------------------------------------------------------------------
# Mapa { dg_name: parent_dg_or_None }
# None  ->  hijo directo de Shared
# Actualiza este diccionario cuando la jerarquía cambie en Panorama.

STATIC_DG_PARENT_MAP: dict[str, str | None] = {
    # Nivel 1 — hijos directos de Shared
    "America":       None,
    "asd":           None,
    "dg_diegotests": None,
    "Europa":        None,
    "us-west-2":     None,
    # Hijos de America
    "Brasil":        "America",
    "dg_target2":    "America",
    "fede_tests":    "America",
    "Uruguay-Tests": "America",
    "US":            "America",
    # Hijos de Europa
    "Espana":        "Europa",
    "Portugal":      "Europa",
    # Hijos de Espana
    "Openbank-ES":   "Espana",
    "Santander-ES":  "Espana",
    # Hijos de us-west-2
    "Dev":           "us-west-2",
    # Añade aquí otros DGs si los hay:
    # "NombreDG": "DGPadre",
}

# ---------------------------------------------------------------------------
# Debug logger
# ---------------------------------------------------------------------------

DEBUG        = False
DEBUG_STDOUT = False
_DBG_FILE    = "debug.txt"
_dbg_fh      = None


def dbg(msg: str) -> None:
    if not DEBUG:
        return
    ts  = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    line = f"[DBG {ts}] {msg}"
    if _dbg_fh:
        _dbg_fh.write(line + "\n")
        _dbg_fh.flush()
    if DEBUG_STDOUT:
        print(line)


# ---------------------------------------------------------------------------
# API helper
# ---------------------------------------------------------------------------

def api_get(params: dict) -> ET.Element:
    log_p = {k: ("***" if k == "key" else v) for k, v in params.items()}
    dbg(f"API -> {log_p}")
    params["key"] = PAN_API_KEY
    try:
        r = requests.get(f"{PAN_URL}/api/", params=params, verify=False, timeout=TIMEOUT)
        r.raise_for_status()
    except requests.RequestException as e:
        sys.exit(f"[ERROR] Conexión con Panorama: {e}")
    dbg(f"API ← HTTP {r.status_code}  len={len(r.text)}")
    dbg(f"     {r.text[:2000]}")
    root = ET.fromstring(r.text)
    status = root.attrib.get("status", "")
    if status != "success":
        msg = root.findtext(".//msg") or r.text[:200]
        if "object not found" in msg.lower():
            dbg("     -> object not found, devolviendo root vacio")
            return root
        sys.exit(f"[ERROR] API status='{status}': {msg}")
    return root


# ---------------------------------------------------------------------------
# Jerarquía de DGs
# ---------------------------------------------------------------------------

def get_ancestor_chain(dg: str) -> list[str]:
    """
    Devuelve la cadena de ancestros [dg, padre, abuelo, ...]
    usando el mapa estático.  Si el DG no está en el mapa, se asume
    que cuelga directamente de Shared.
    """
    if dg not in STATIC_DG_PARENT_MAP:
        print(f"[WARN] '{dg}' no está en STATIC_DG_PARENT_MAP — se asume hijo directo de Shared.")
        dbg(f"get_ancestor_chain: '{dg}' no en mapa, devolviendo ['{dg}']")
        return [dg]

    chain: list[str] = []
    current: str | None = dg
    visited: set[str]   = set()
    while current is not None and current not in visited:
        chain.append(current)
        visited.add(current)
        current = STATIC_DG_PARENT_MAP.get(current)   # None si es raíz

    dbg(f"get_ancestor_chain('{dg}') -> {chain}")
    return chain   # [dg, padre, abuelo, ...]


def get_evaluation_order(dg: str) -> list[tuple[str, str]]:
    """
    Retorna la lista de (scope, rulebase) en el orden que PAN-OS evalúa:
      shared/pre -> [abuelo/pre -> padre/pre ->] dg/pre
      -> dg/post [-> padre/post -> abuelo/post] -> shared/post
    """
    chain = get_ancestor_chain(dg)   # [dg, padre, abuelo, ...]
    # Pre-rulebase: shared primero, luego ancestros de raíz a hoja
    pre_scopes  = ["shared"] + list(reversed(chain))   # shared, abuelo, padre, dg
    # Post-rulebase: dg primero, luego ancestros de hoja a raíz, shared al final
    post_scopes = list(chain) + ["shared"]             # dg, padre, abuelo, shared

    order = (
        [(s, "pre-rulebase")  for s in pre_scopes] +
        [(s, "post-rulebase") for s in post_scopes]
    )
    dbg(f"evaluation_order para '{dg}': {order}")
    return order


# ---------------------------------------------------------------------------
# Obtención de reglas
# ---------------------------------------------------------------------------

def fetch_rules(scope: str, rulebase: str) -> list[ET.Element]:
    """Devuelve los <entry> de las reglas de seguridad de un scope/rulebase."""
    if scope.lower() == "shared":
        xpath = f"/config/shared/{rulebase}/security/rules"
    else:
        xpath = (
            "/config/devices/entry[@name='localhost.localdomain']"
            f"/device-group/entry[@name='{scope}']/{rulebase}/security/rules"
        )
    root = api_get({"type": "config", "action": "get", "xpath": xpath})
    rules = root.findall(".//rules/entry")
    dbg(f"fetch_rules({scope!r}, {rulebase!r}) -> {len(rules)} regla(s)")
    return rules


# ---------------------------------------------------------------------------
# Objetos de servicio
# ---------------------------------------------------------------------------

# Servicios predefinidos de PAN-OS (built-in, no aparecen en la config XML).
# Se incluyen siempre en la resolución de servicios.
_BUILTIN_SERVICES: dict[str, dict] = {
    "service-http":  {"proto": "tcp", "ports": [80]},
    "service-https": {"proto": "tcp", "ports": [443]},
}

def fetch_services(scope: str) -> dict[str, dict]:
    """
    Descarga los objetos de servicio de un scope y devuelve
    { nombre: {"proto": "tcp"|"udp", "ports": [int, ...]} }
    """
    if scope.lower() == "shared":
        xpath = "/config/shared/service"
    else:
        xpath = (
            "/config/devices/entry[@name='localhost.localdomain']"
            f"/device-group/entry[@name='{scope}']/service"
        )
    root = api_get({"type": "config", "action": "get", "xpath": xpath})
    svc_map: dict[str, dict] = {}
    for entry in root.findall(".//service/entry"):
        name = entry.attrib.get("name", "")
        if not name:
            continue
        tcp_el = entry.find(".//protocol/tcp/port")
        udp_el = entry.find(".//protocol/udp/port")
        if tcp_el is not None and tcp_el.text:
            ports = _parse_port_range(tcp_el.text)
            svc_map[name] = {"proto": "tcp", "ports": ports}
        elif udp_el is not None and udp_el.text:
            ports = _parse_port_range(udp_el.text)
            svc_map[name] = {"proto": "udp", "ports": ports}
    dbg(f"fetch_services({scope!r}) -> {len(svc_map)} servicio(s): {list(svc_map)}")
    return svc_map


def _parse_port_range(text: str) -> list[int]:
    """Parsea '80,443,8080-8090' -> lista de enteros."""
    ports: list[int] = []
    for part in text.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            try:
                ports.extend(range(int(lo), int(hi) + 1))
            except ValueError:
                pass
        else:
            try:
                ports.append(int(part))
            except ValueError:
                pass
    return ports


# ---------------------------------------------------------------------------
# Custom URL Categories
# ---------------------------------------------------------------------------

def fetch_custom_url_categories(scope: str) -> dict[str, list[str]]:
    """
    Descarga las categorias URL personalizadas (Objects > Custom URL Categories)
    de un scope y devuelve {nombre_cat: [patron_url, ...]}.
    Nota: las categorias predefinidas de PAN-OS NO aparecen en la config XML.
    """
    if scope.lower() == "shared":
        xpath = "/config/shared/profiles/custom-url-category"
    else:
        xpath = (
            "/config/devices/entry[@name='localhost.localdomain']"
            f"/device-group/entry[@name='{scope}']/profiles/custom-url-category"
        )
    root = api_get({"type": "config", "action": "get", "xpath": xpath})
    cat_map: dict[str, list[str]] = {}
    for entry in root.findall(".//custom-url-category/entry"):
        name = entry.attrib.get("name", "")
        urls = [m.text.strip() for m in entry.findall(".//list/member") if m.text]
        if name:
            cat_map[name] = urls
    dbg(f"fetch_custom_url_categories({scope!r}) -> {len(cat_map)} cat(s): {list(cat_map)}")
    return cat_map


def extract_domain(url: str) -> str:
    """Extrae el hostname/dominio de una URL o de un nombre de dominio directo."""
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    try:
        parsed = urlparse(url)
        return (parsed.hostname or url).lower()
    except Exception:
        return url.lower()


def domain_matches_pattern(domain: str, pattern: str) -> bool:
    """
    Comprueba si un dominio coincide con un patron de URL de PAN-OS.
    Soporta:
      - Exact:     "google.com"     -> solo google.com
      - Wildcard:  "*.google.com"   -> cualquier subdominio de google.com
      - Dot-prefix: ".google.com"   -> equivalente a *.google.com en PAN-OS
      - Con path:  "google.com/x"   -> solo se compara la parte host
    """
    domain  = domain.lower().rstrip(".")
    pattern = pattern.lower().strip()

    # Quitar protocolo si lo tuviera
    if "://" in pattern:
        pattern = pattern.split("://", 1)[1]

    # Solo la parte host (ignorar path)
    pattern_host = pattern.split("/")[0]

    if pattern_host.startswith("*."):
        # *.google.com  -> subdominio de google.com (no el propio google.com)
        base = pattern_host[2:]
        return domain == base or domain.endswith("." + base)
    elif pattern_host.startswith("."):
        # .google.com  -> equivalente PAN-OS a *.google.com
        base = pattern_host[1:]
        return domain == base or domain.endswith("." + base)
    else:
        # Coincidencia exacta o subdominio del patron
        return domain == pattern_host or domain.endswith("." + pattern_host)


def url_category_check(
    url:            str | None,
    rule_url_cats:  list[str],
    custom_url_dbs: list[dict[str, list[str]]],
) -> tuple[bool, str]:
    """
    Comprueba si la URL del usuario coincide con la url-category de la regla.

    Devuelve (match: bool, motivo: str):
      - Si no se especifico URL -> True (sin filtro)
      - Si la regla no tiene url-category o es 'any' -> True
      - Si la categoria es una custom URL category:
          - Si el dominio coincide con alguna entrada -> True
          - Si no coincide -> False
      - Si la categoria es predefinida de PAN-OS (no en config XML):
          - Se trata como coincidencia posible y se indica en el motivo
    """
    if not url:
        return True, ""

    if not rule_url_cats or _has_any(rule_url_cats):
        return True, ""   # sin restriccion de URL category

    domain = extract_domain(url)
    dbg(f"  url_category_check: domain='{domain}' cats={rule_url_cats}")

    unresolvable: list[str] = []

    for cat in rule_url_cats:
        # Buscar en custom URL categories de todos los scopes
        cat_entries: list[str] | None = None
        for db in custom_url_dbs:
            if cat in db:
                cat_entries = db[cat]
                break

        if cat_entries is not None:
            # Categoria personalizada: verificar si el dominio esta en la lista
            for entry in cat_entries:
                if domain_matches_pattern(domain, entry):
                    dbg(f"  url_category_check: MATCH -> '{domain}' en custom-cat '{cat}' (entry='{entry}')")
                    return True, f"URL '{domain}' en categoria personalizada '{cat}'"
        else:
            # Categoria predefinida de PAN-OS: no tenemos su contenido
            unresolvable.append(cat)
            dbg(f"  url_category_check: categoria predefinida '{cat}' - no verificable")

    if unresolvable:
        # Hay categorias predefinidas que no podemos verificar;
        # las tratamos como coincidencia posible (conservador).
        note = f"Categorias predefinidas PAN-OS {unresolvable} - no verificables, asumido match"
        dbg(f"  url_category_check: {note}")
        return True, note

    dbg(f"  url_category_check: MISS -> '{domain}' no en url-categories={rule_url_cats}")
    return False, f"URL '{domain}' no coincide con url-category={rule_url_cats}"


# ---------------------------------------------------------------------------
# Helpers de evaluación de regla
# ---------------------------------------------------------------------------

def _members(entry: ET.Element, tag: str) -> list[str]:
    return [m.text.strip() for m in entry.findall(f".//{tag}/member") if m.text]


def _has_any(vals: list[str]) -> bool:
    return any(v.lower() == "any" for v in vals)


def parse_port_arg(s: str) -> tuple[str | None, int | None]:
    """'udp/53' -> ('udp', 53) | '443' -> (None, 443) | '' -> (None, None)"""
    if not s:
        return None, None
    s = s.strip().lower()
    if "/" in s:
        proto, port = s.split("/", 1)
        try:
            return proto, int(port)
        except ValueError:
            sys.exit(f"[ERROR] Puerto inválido: {s}")
    try:
        return None, int(s)
    except ValueError:
        sys.exit(f"[ERROR] Puerto inválido: {s}")


def ip_in_members(ip_str: str | None, members: list[str]) -> bool:
    if not ip_str:
        return True       # no especificado -> no filtramos
    if _has_any(members):
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for m in members:
        try:
            if "/" in m:
                if ip in ipaddress.ip_network(m, strict=False):
                    return True
            else:
                if ip == ipaddress.ip_address(m):
                    return True
        except ValueError:
            continue
    return False


def zone_matches(zone: str | None, members: list[str]) -> bool:
    if not zone:
        return True
    if _has_any(members):
        return True
    return zone.lower() in [m.lower() for m in members]


def app_matches(app: str | None, apps: list[str], ignore: bool) -> bool:
    if ignore or not app:
        return True
    if _has_any(apps):
        return True
    return app.lower() in [a.lower() for a in apps]


# Mapa de servicios por defecto de aplicaciones PAN-OS conocidas.
# Formato: { app_name: [(proto, {puerto, ...}), ...] }
# - set vacio en puertos = sin restriccion de puerto para ese protocolo (ej: ICMP)
# - Usado para evaluar 'application-default': la regla solo aplica si el trafico
#   coincide con proto Y puerto del app-default de la aplicacion.

_APP_DEFAULT: dict[str, list[tuple[str, set[int]]]] = {
    # ICMP
    "icmp":          [("icmp", set())],
    "ping":          [("icmp", set())],
    "ping6":         [("icmp", set())],
    "icmpv6":        [("icmp", set())],
    "traceroute":    [("icmp", set()), ("udp", {33434, 33435, 33436})],
    # DNS
    "dns":           [("udp", {53}), ("tcp", {53})],
    "dns-base":      [("udp", {53}), ("tcp", {53})],
    # DHCP
    "dhcp":          [("udp", {67, 68})],
    "dhcpv6":        [("udp", {546, 547})],
    # NTP / SNMP / TFTP / Syslog
    "ntp":           [("udp", {123})],
    "snmp":          [("udp", {161, 162})],
    "tftp":          [("udp", {69})],
    "syslog":        [("udp", {514})],
    # RADIUS / TACACS
    "radius":        [("udp", {1812, 1813, 1645, 1646})],
    "tacacs-plus":   [("tcp", {49})],
    # LDAP
    "ldap":          [("tcp", {389}), ("udp", {389})],
    "ldaps":         [("tcp", {636})],
    # HTTP / HTTPS / SSL (aplicaciones web genericas)
    "http":          [("tcp", {80, 8080})],
    "http2":         [("tcp", {80, 443, 8080, 8443})],
    "ssl":           [("tcp", {443, 8443})],
    "web-browsing":  [("tcp", {80})],
    # FTP / SFTP / SCP
    "ftp":           [("tcp", {20, 21})],
    "ftps":          [("tcp", {990})],
    "sftp":          [("tcp", {22})],
    # SSH / Telnet
    "ssh":           [("tcp", {22})],
    "telnet":        [("tcp", {23})],
    # Mail
    "smtp":          [("tcp", {25})],
    "smtps":         [("tcp", {465})],
    "smtp-base":     [("tcp", {25})],
    "imap":          [("tcp", {143})],
    "imaps":         [("tcp", {993})],
    "pop3":          [("tcp", {110})],
    "pop3s":         [("tcp", {995})],
    # Remote access
    "rdp":           [("tcp", {3389})],
    "vnc":           [("tcp", {5900, 5901})],
    # File sharing
    "smb":           [("tcp", {445})],
    "netbios-ns":    [("udp", {137})],
    "netbios-dgm":   [("udp", {138})],
    "netbios-ss":    [("tcp", {139})],
    # Databases
    "mssql":         [("tcp", {1433})],
    "mysql":         [("tcp", {3306})],
    "oracle":        [("tcp", {1521})],
    "postgresql":    [("tcp", {5432})],
    "redis":         [("tcp", {6379})],
    # VPN / Tunneling
    "ipsec":         [("udp", {500, 4500})],
    "isakmp":        [("udp", {500})],
    "openvpn":       [("udp", {1194}), ("tcp", {1194})],
    # VoIP
    "sip":           [("udp", {5060}), ("tcp", {5060})],
    "sips":          [("tcp", {5061})],
    "rtp":           [("udp", set())],
    # Otros de red
    "kerberos":      [("tcp", {88}), ("udp", {88})],
    "nfs":           [("tcp", {2049}), ("udp", {2049})],
    "bgp":           [("tcp", {179})],
    "ospf":          [("tcp", set())],
    # Aplicaciones web / SaaS (tcp/80 y tcp/443)
    # PAN-OS identifica estas apps principalmente en puertos web estandar.
    "openai":                    [("tcp", {80, 443})],
    "chatgpt":                   [("tcp", {80, 443})],
    "google-base":               [("tcp", {80, 443})],
    "google":                    [("tcp", {80, 443})],
    "youtube":                   [("tcp", {80, 443})],
    "facebook":                  [("tcp", {80, 443})],
    "instagram":                 [("tcp", {80, 443})],
    "twitter":                   [("tcp", {80, 443})],
    "linkedin":                  [("tcp", {80, 443})],
    "microsoft-update":          [("tcp", {80, 443})],
    "office365":                 [("tcp", {80, 443})],
    "ms-office365":              [("tcp", {80, 443})],
    "sharepoint":                [("tcp", {80, 443})],
    "onedrive":                  [("tcp", {80, 443})],
    "outlook":                   [("tcp", {80, 443})],
    "teams":                     [("tcp", {80, 443})],
    "ms-teams":                  [("tcp", {80, 443})],
    "zoom":                      [("tcp", {80, 443}), ("udp", {8801, 8802})],
    "webex":                     [("tcp", {80, 443})],
    "slack":                     [("tcp", {80, 443})],
    "dropbox":                   [("tcp", {80, 443})],
    "box":                       [("tcp", {80, 443})],
    "salesforce":                [("tcp", {80, 443})],
    "github":                    [("tcp", {80, 443, 22})],
    "github-base":               [("tcp", {80, 443})],
    "aws":                       [("tcp", {80, 443})],
    "amazon-aws":                [("tcp", {80, 443})],
    "azure":                     [("tcp", {80, 443})],
    "gcp":                       [("tcp", {80, 443})],
    "adobe-media-server":        [("tcp", {80, 443})],
    "adobe-media-player":        [("tcp", {80, 443})],
    "netflix":                   [("tcp", {80, 443})],
    "spotify":                   [("tcp", {80, 443})],
    "apple-push-notifications":  [("tcp", {443, 5223})],
}

# Para service=any: solo verificamos protocolo (sin restriccion de puerto)
# Formato simple {app: frozenset(protos)}
_APP_PROTO_ONLY: dict[str, frozenset] = {
    app: frozenset(p for p, _ in entries)
    for app, entries in _APP_DEFAULT.items()
}


# Puertos TCP estandar usados como fallback cuando la app es desconocida
# y service=application-default. La gran mayoria de apps modernas usan
# TCP/80 y TCP/443. Si el trafico va a otro puerto, no se considera match.
_UNKNOWN_APP_DEFAULT_TCP_PORTS: frozenset[int] = frozenset({80, 443})


def traffic_matches_app_default(
    rule_apps: list[str],
    proto:     str | None,
    port:      int | None,
) -> bool:
    """
    Para service=application-default: comprueba que el trafico (proto, port)
    coincida con algun servicio por defecto de alguna app de la regla.

    Reglas:
    - app=any -> True (sin restriccion)
    - app conocida en _APP_DEFAULT:
        - proto debe coincidir con el proto del app-default
        - si el app-default tiene puertos: port debe estar en ellos
        - si el app-default no tiene puertos (ej ICMP): solo se verifica proto
    - app desconocida:
        - Si no se especifica proto/puerto -> True (sin informacion, no filtramos)
        - Si proto=tcp: solo match en puertos web estandar {80, 443}
        - Si proto=udp o icmp -> NO match (apps desconocidas se asumen TCP/web)
    """
    if _has_any(rule_apps):
        return True
    if not proto and port is None:
        return True   # sin filtro de puerto -> no podemos descartar

    proto_l = (proto or "").lower()

    for app in rule_apps:
        defaults = _APP_DEFAULT.get(app.lower())
        if defaults is None:
            # App desconocida: solo match en puertos web estandar TCP
            if proto_l == "tcp" or not proto_l:
                if port is None or port in _UNKNOWN_APP_DEFAULT_TCP_PORTS:
                    return True
            # UDP/ICMP o puerto no estandar con app desconocida -> no match
            continue

        for def_proto, def_ports in defaults:
            # Verificar protocolo
            if proto_l and def_proto != proto_l:
                continue
            # Verificar puerto (si hay puertos definidos y el usuario especifico uno)
            if port is not None and def_ports and port not in def_ports:
                continue
            return True   # proto coincide y puerto dentro del rango

    return False


def apps_compatible_with_proto_only(
    rule_apps: list[str],
    proto:     str | None,
) -> bool:
    """
    Para service=any: solo verifica compatibilidad de protocolo (sin restriccion de puerto).
    App desconocida -> True (no podemos descartar).
    """
    if not proto or _has_any(rule_apps):
        return True
    proto_l = proto.lower()
    for app in rule_apps:
        known = _APP_PROTO_ONLY.get(app.lower())
        if known is None:
            return True          # desconocida -> no filtramos
        if proto_l in known:
            return True
    return False


def port_matches_services(
    proto:    str | None,
    port:     int | None,
    services: list[str],
    svc_dbs:  list[dict],
) -> bool:
    """
    Comprueba si el par (proto, port) encaja con la lista de servicios de la regla.
    services puede ser ['any'], ['application-default'], o nombres de objetos.

    Nota: 'application-default' NO se trata como permisivo aqui; el filtrado por
    compatibilidad proto<->app se realiza en evaluate_rule con strict_for_unknown=True.
    """
    if not proto and port is None:
        return True        # no especificado -> no filtramos

    svcs_lower = [s.lower() for s in services]

    if "any" in svcs_lower:
        return True        # any -> sin restriccion de puerto

    if "application-default" in svcs_lower:
        # No retornamos True aqui; dejamos que evaluate_rule compruebe
        # la compatibilidad proto<->app con strict_for_unknown=True.
        # Si hay otros servicios concretos en la lista, los evaluamos igualmente.
        other_svcs = [s for s in services if s.lower() not in ("any", "application-default")]
        if not other_svcs:
            # Solo application-default: el match de puerto lo gestiona evaluate_rule
            return True
        # Hay servicios concretos ademas de application-default -> evaluamos esos
        for svc_name in other_svcs:
            for db in svc_dbs:
                if svc_name in db:
                    obj = db[svc_name]
                    if proto and obj["proto"] != proto.lower():
                        continue
                    if port is None or port in obj["ports"]:
                        return True
        return False

    # Servicios concretos: buscar primero en built-ins, luego en svc_dbs
    for svc_name in services:
        # Servicios predefinidos PAN-OS (service-http, service-https)
        builtin = _BUILTIN_SERVICES.get(svc_name.lower()) or _BUILTIN_SERVICES.get(svc_name)
        obj = builtin
        if obj is None:
            for db in svc_dbs:
                if svc_name in db:
                    obj = db[svc_name]
                    break
        if obj is None:
            dbg(f"  svc '{svc_name}' no encontrado en built-ins ni en svc_dbs")
            continue
        if proto and obj["proto"] != proto.lower():
            continue
        if port is None or port in obj["ports"]:
            return True

    return False


# ---------------------------------------------------------------------------
# Evaluación de una regla individual
# ---------------------------------------------------------------------------

def rule_is_disabled(entry: ET.Element) -> bool:
    d = entry.findtext("disabled") or entry.findtext(".//disabled") or ""
    return d.strip().lower() in ("yes", "true", "1")


def rule_action(entry: ET.Element) -> str:
    return (entry.findtext("action") or "deny").strip().lower()


def evaluate_rule(
    entry:          ET.Element,
    src_ip:         str | None,
    dst_ip:         str | None,
    src_zone:       str | None,
    dst_zone:       str | None,
    app:            str | None,
    ignore_app:     bool,
    dst_proto:      str | None,
    dst_port:       int | None,
    src_proto:      str | None,
    src_port:       int | None,
    svc_dbs:        list[dict],
    url:            str | None,
    custom_url_dbs: list[dict[str, list[str]]],
) -> tuple[bool, str]:
    """
    Evalúa si la regla hace match.
    Devuelve (match: bool, razon_descarte: str).
    razon_descarte está vacío si hay match.
    """
    name = entry.attrib.get("name", "?")

    if rule_is_disabled(entry):
        return False, "disabled=yes"

    # IPs
    src_members = _members(entry, "source")
    if not ip_in_members(src_ip, src_members):
        return False, f"src-ip '{src_ip}' ∉ source={src_members}"

    dst_members = _members(entry, "destination")
    if not ip_in_members(dst_ip, dst_members):
        return False, f"dst-ip '{dst_ip}' ∉ destination={dst_members}"

    # Zonas
    from_zones = _members(entry, "from")
    if not zone_matches(src_zone, from_zones):
        return False, f"src-zone '{src_zone}' ∉ from={from_zones}"

    to_zones = _members(entry, "to")
    if not zone_matches(dst_zone, to_zones):
        return False, f"dst-zone '{dst_zone}' ∉ to={to_zones}"

    # Aplicación
    apps = _members(entry, "application")
    if not app_matches(app, apps, ignore_app):
        return False, f"app '{app}' ∉ application={apps}"

    # Servicios / puertos
    services = _members(entry, "service")
    svcs_lower = [s.lower() for s in services]
    is_app_default = "application-default" in svcs_lower
    is_any_svc     = "any" in svcs_lower or not svcs_lower
    dbg(f"  svc raw={services}  is_app_default={is_app_default}  is_any={is_any_svc}")

    effective_proto = dst_proto or src_proto
    effective_port  = dst_port  if dst_proto else src_port

    if is_app_default and not is_any_svc:
        # service=application-default: el firewall identifica la app via App-ID y solo
        # aplica la regla si la app coincide Y el trafico va por los puertos por defecto.
        #
        # Si la regla tiene apps especificas (no "any"):
        #   - Usuario especifico --app: comprobamos proto+puerto contra los defaults de la app
        #   - Usuario uso --ignore-app: pasamos (el usuario pide ignorar la app)
        #   - Usuario NO especifico --app: NO podemos predecir que detectara App-ID
        #     -> se descarta la regla para evitar falsos positivos
        rule_has_specific_apps = apps and not _has_any(apps)
        user_specified_app     = app is not None   # True solo si el usuario paso --app

        if rule_has_specific_apps and not user_specified_app and not ignore_app:
            return False, (
                f"service=application-default con apps={apps}: sin --app especificado "
                f"no se puede predecir el comportamiento de App-ID"
            )

        # Con app conocida (o ignore_app=True con app=any), comprobamos proto+puerto
        if not traffic_matches_app_default(apps, effective_proto, effective_port):
            return False, (
                f"trafico {effective_proto}/{effective_port} no coincide con "
                f"app-default de apps={apps}"
            )
    else:
        # service=any o servicio concreto
        if not port_matches_services(dst_proto, dst_port, services, svc_dbs):
            return False, f"dst-port {dst_proto}/{dst_port} no coincide con services={services}"
        if not port_matches_services(src_proto, src_port, services, svc_dbs):
            return False, f"src-port {src_proto}/{src_port} no coincide con services={services}"
        # Para service=any: verificar compatibilidad proto<->app (sin restriccion de puerto)
        if is_any_svc and effective_proto:
            if not apps_compatible_with_proto_only(apps, effective_proto):
                return False, (
                    f"proto '{effective_proto}' incompatible con apps={apps} (service=any)"
                )

    # URL category
    # Nota: en PAN-OS el campo URL Category de las reglas se llama <category> en el XML,
    # NO <url-category>. Este ultimo se usa en perfiles de URL filtering.
    rule_url_cats = _members(entry, "category")
    dbg(f"  url-category (XML tag=category) raw={rule_url_cats}")
    url_ok, url_reason = url_category_check(url, rule_url_cats, custom_url_dbs)
    if not url_ok:
        return False, url_reason

    return True, ""


# ---------------------------------------------------------------------------
# Formateo del resultado
# ---------------------------------------------------------------------------

def format_result(
    args,
    chain:           list[str],
    evaluation_order: list[tuple[str, str]],
    matched_rule:    ET.Element | None,
    matched_scope:   str,
    matched_rulebase: str,
) -> str:
    SEP = "=" * 72
    lines = [
        "",
        SEP,
        "  Panorama Policy Test — Regla aplicable",
        SEP,
        f"  Panorama     : {PAN_URL}",
        f"  Device Group : {args.device_group}",
        f"  Jerarquía    : shared -> {' -> '.join(reversed(chain))}",
    ]
    if args.src_ip:
        lines.append(f"  IP origen    : {args.src_ip}")
    if args.dst_ip:
        lines.append(f"  IP destino   : {args.dst_ip}")
    if args.src_port:
        lines.append(f"  Puerto orig  : {args.src_port}")
    if args.dst_port:
        lines.append(f"  Puerto dest  : {args.dst_port}")
    if args.src_zone:
        lines.append(f"  Zona origen  : {args.src_zone}")
    if args.dst_zone:
        lines.append(f"  Zona destino : {args.dst_zone}")
    if args.app:
        lines.append(f"  Aplicacion   : {args.app}")
    if getattr(args, "ignore_app", False):
        lines.append("  Aplicacion   : (ignorada)")
    if getattr(args, "url", None):
        lines.append(f"  URL          : {args.url}")
    lines.append(SEP)
    lines.append("")

    if matched_rule is None:
        lines += [
            "  RESULTADO: No se encontró ninguna regla que aplique.",
            "  (Aplicaría la regla implícita de denegación — default deny)",
            "",
            SEP,
        ]
        return "\n".join(lines)

    action   = rule_action(matched_rule)
    icon     = "[ALLOW] ALLOW" if action == "allow" else "[DENY] DENY"
    name     = matched_rule.attrib.get("name", "?")
    src_m    = ", ".join(_members(matched_rule, "source")) or "any"
    dst_m    = ", ".join(_members(matched_rule, "destination")) or "any"
    src_z    = ", ".join(_members(matched_rule, "from")) or "any"
    dst_z    = ", ".join(_members(matched_rule, "to")) or "any"
    apps     = ", ".join(_members(matched_rule, "application")) or "any"
    svcs     = ", ".join(_members(matched_rule, "service")) or "any"
    url_cats = ", ".join(_members(matched_rule, "category")) or "any"
    desc_el  = matched_rule.find("description")
    desc     = (desc_el.text or "").strip() if desc_el is not None else ""
    tags     = ", ".join(_members(matched_rule, "tag")) or "(sin tags)"
    prof_el  = matched_rule.find("profile-setting/group")
    profile  = (prof_el.text or "").strip() if prof_el is not None else "(sin perfil)"

    lines += [
        f"  RESULTADO: [{icon}]  Primera regla que aplica:",
        "",
        f"  Nombre       : {name}",
        f"  Ambito       : {matched_scope} / {matched_rulebase}",
        f"  Accion       : {action.upper()}",
        f"  Zona origen  : {src_z}",
        f"  Zona destino : {dst_z}",
        f"  Source       : {src_m}",
        f"  Destination  : {dst_m}",
        f"  Aplicacion   : {apps}",
        f"  Servicio     : {svcs}",
        f"  URL Category : {url_cats}",
        f"  Perfil seg.  : {profile}",
        f"  Tags         : {tags}",
    ]
    if desc:
        lines.append(f"  Descripcion  : {desc}")
    lines += ["", SEP]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Función principal de evaluación
# ---------------------------------------------------------------------------

def run_policy_test(args) -> str:
    # 1. Jerarquía
    chain = get_ancestor_chain(args.device_group)
    print(f"[INFO] Cadena jerárquica : shared -> {' -> '.join(reversed(chain))}")

    # 2. Orden de evaluación
    evaluation_order = get_evaluation_order(args.device_group)
    ev_str = "  ->  ".join(f"{s}/{r.split('-')[0]}" for s, r in evaluation_order)
    print(f"[INFO] Orden evaluación  : {ev_str}")
    print()

    # 3. Cargar objetos de servicio y URL categories de todos los scopes
    all_scopes = ["shared"] + list(reversed(chain))
    print("[INFO] Cargando objetos de servicio...")
    svc_dbs: list[dict] = []
    for scope in all_scopes:
        db = fetch_services(scope)
        svc_dbs.append(db)
        print(f"  [{scope}] {len(db)} servicio(s)")
    print()

    url = getattr(args, "url", None)
    custom_url_dbs: list[dict[str, list[str]]] = []
    if url:
        print("[INFO] Cargando custom URL categories...")
        for scope in all_scopes:
            db = fetch_custom_url_categories(scope)
            custom_url_dbs.append(db)
            print(f"  [{scope}] {len(db)} categoria(s)")
        print()
    else:
        # Sin URL especificada: lista de dicts vacios (url_category_check devolvera True)
        custom_url_dbs = [{} for _ in all_scopes]

    # 4. Parsear puertos
    src_proto, src_port = parse_port_arg(args.src_port or "")
    dst_proto, dst_port = parse_port_arg(args.dst_port or "")

    # 5. Evaluar reglas en orden
    print("[INFO] Evaluando reglas...")
    matched_rule:     ET.Element | None = None
    matched_scope:    str = ""
    matched_rulebase: str = ""

    if DEBUG:
        dbg("=" * 60)
        dbg(f"PARÁMETROS: src={args.src_ip} dst={args.dst_ip} "
            f"src_port={args.src_port} dst_port={args.dst_port} "
            f"src_zone={args.src_zone} dst_zone={args.dst_zone} "
            f"app={args.app} ignore_app={getattr(args,'ignore_app',False)}")
        dbg(f"ORDEN: {evaluation_order}")
        dbg("=" * 60)

    for scope, rulebase in evaluation_order:
        print(f"  [{scope}] {rulebase} ...", end=" ", flush=True)
        rules = fetch_rules(scope, rulebase)
        print(f"{len(rules)} regla(s)")
        dbg(f"RULEBASE [{scope}] {rulebase} -> {len(rules)} regla(s)")

        for rule in rules:
            rname = rule.attrib.get("name", "?")
            dbg(f"  EVAL '{rname}'")
            match, reason = evaluate_rule(
                rule,
                src_ip         = args.src_ip,
                dst_ip         = args.dst_ip,
                src_zone       = args.src_zone,
                dst_zone       = args.dst_zone,
                app            = args.app,
                ignore_app     = getattr(args, "ignore_app", False),
                dst_proto      = dst_proto,
                dst_port       = dst_port,
                src_proto      = src_proto,
                src_port       = src_port,
                svc_dbs        = svc_dbs,
                url            = url,
                custom_url_dbs = custom_url_dbs,
            )
            if match:
                dbg(f"  MATCH -> '{rname}'")
                matched_rule     = rule
                matched_scope    = scope
                matched_rulebase = rulebase
                break
            else:
                dbg(f"  MISS  -> {reason}")

        if matched_rule is not None:
            break

    print()
    return format_result(args, chain, evaluation_order, matched_rule, matched_scope, matched_rulebase)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Panorama Policy Test — determina qué regla aplicaría a un flujo de tráfico.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--device-group", required=True, metavar="DG",
                        help="Device Group objetivo (obligatorio).")
    parser.add_argument("--src-ip",   metavar="IP",    default=None, help="IP de origen.")
    parser.add_argument("--dst-ip",   metavar="IP",    default=None, help="IP de destino.")
    parser.add_argument("--src-port", metavar="PUERTO",default=None,
                        help="Puerto origen: numero, tcp/num o udp/num.")
    parser.add_argument("--dst-port", metavar="PUERTO",default=None,
                        help="Puerto destino: numero, tcp/num o udp/num.")
    parser.add_argument("--src-zone", metavar="ZONA",  default=None, help="Zona de origen.")
    parser.add_argument("--dst-zone", metavar="ZONA",  default=None, help="Zona de destino.")
    parser.add_argument("--app",      metavar="APP",   default=None, help="Aplicacion PAN-OS.")
    parser.add_argument("--ignore-app", dest="ignore_app", action="store_true", default=False,
                        help="Ignora la aplicacion al evaluar reglas.")
    parser.add_argument("--url",      metavar="URL",   default=None,
                        help="URL a comprobar contra el campo url-category de las reglas.\n"
                             "Ejemplo: --url https://google.com  o  --url malware.example.com\n"
                             "Las categorias predefinidas PAN-OS no se pueden resolver\n"
                             "(se tratan como coincidencia posible).")
    parser.add_argument("--output",   metavar="FICHERO",default=None,
                        help="Guarda el resultado en un fichero.")
    parser.add_argument("--debug",    action="store_true", default=False,
                        help="Escribe traza detallada en debug.txt.")
    parser.add_argument("--debug-stdout", dest="debug_stdout", action="store_true", default=False,
                        help="Además de debug.txt, muestra las trazas por consola.")
    return parser.parse_args()


def main() -> None:
    global DEBUG, DEBUG_STDOUT, _dbg_fh
    args = parse_args()

    DEBUG        = args.debug
    DEBUG_STDOUT = getattr(args, "debug_stdout", False)

    if DEBUG:
        _dbg_fh = open(_DBG_FILE, "w", encoding="utf-8")
        dbg("=" * 60)
        dbg(f"SESIÓN  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        dbg(f"PAN_URL={PAN_URL}")
        dbg(f"args={vars(args)}")
        dbg("=" * 60)
        print(f"[DEBUG] Modo debug activo -> {_DBG_FILE}")

    # Validar IPs
    for ip_arg, label in [(args.src_ip, "--src-ip"), (args.dst_ip, "--dst-ip")]:
        if ip_arg:
            try:
                ipaddress.ip_address(ip_arg)
            except ValueError:
                sys.exit(f"[ERROR] {label}: '{ip_arg}' no es una IP válida.")

    try:
        result = run_policy_test(args)
    finally:
        if _dbg_fh:
            dbg("=" * 60)
            dbg("FIN DE SESIÓN")
            _dbg_fh.close()

    print(result)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(result)
        print(f"[INFO] Resultado guardado en: {args.output}")

    if DEBUG:
        print(f"[DEBUG] Log guardado en: {_DBG_FILE}")


if __name__ == "__main__":
    main()
