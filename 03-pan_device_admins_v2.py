#!/usr/bin/env python3
"""
03-pan_device_admins.py
-----------------------
Auditoría de seguridad de accesos en firewalls Palo Alto Networks gestionados
por Panorama. Usa Panorama como proxy de API (parámetro target=<serial>) para
consultar cada firewall, y consulta directamente los templates de Panorama
cuando la configuración del firewall viene de una plantilla (src="tpl").

IMPORTANTE — Lógica de fallback a template:
  Muchos firewalls gestionados por Panorama no tienen config local para
  auth-profiles, server-profiles, syslog, etc. — todo viene del template
  asignado (atributo src="tpl" en el XML). El script detecta esto y lee
  la config directamente desde el template en Panorama.

Secciones recogidas por firewall:
  1.  Admins: rol, estado (ACTIVO/DESHABILITADO/BLOQUEADO),
              tipo LOCAL o REMOTO (servidor que autentica),
              política de contraseñas aplicable.
  2.  Roles personalizados: scope de vsys + usuarios que los tienen.
  3.  Auth profiles: LOCAL vs EXTERNO con IP del servidor y usuarios autenticados.
  4.  Política de contraseñas (global del dispositivo).
  5.  Authentication sequences (delegación).
  6.  Usuarios y grupos locales con pertenencia a grupos.
  7.  Vsys reales del dispositivo y admins con acceso a cada uno.
  8.  Servidores AAA (nombres e IPs) vinculados a los auth profiles del punto 3.
  9.  Group mapping de dominio (AD/LDAP).
 10.  Templates y Template Stacks de Panorama asignados.
 12.  Log Forwarding Profiles (Objects > Log Forwarding) + Device Log Settings.
 13.  Servidores Syslog.
 15.  Fuentes de gestión permitidas (Permitted IP).

Uso:
  python 03-pan_device_admins.py
  python 03-pan_device_admins.py --sn 007957000675956
  python 03-pan_device_admins.py --device-name FW-MADRID-01
  python 03-pan_device_admins.py --device-group DG-PRODUCCION
  python 03-pan_device_admins.py --output auditoria.csv
  python 03-pan_device_admins.py --group-by firewall|user|both
  python 03-pan_device_admins.py --debug

Requisitos (.env):
  PAN_URL=https://<panorama-ip-o-fqdn>
  PAN_API_KEY=<api-key>
"""

import argparse
import csv
import os
import sys
import urllib3
import xml.etree.ElementTree as ET
from datetime import datetime

import requests
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Configuración inicial
# ---------------------------------------------------------------------------

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

PAN_URL     = os.getenv("PAN_URL", "").rstrip("/")
PAN_API_KEY = os.getenv("PAN_API_KEY", "")

if not PAN_URL or not PAN_API_KEY:
    sys.exit("[ERROR] PAN_URL y PAN_API_KEY deben estar definidas en el fichero .env")

TIMEOUT_PANORAMA = 30
TIMEOUT_DEVICE   = 45

DEBUG_LINES: list[str] = []

EXTERNAL_AUTH_METHODS = {"radius", "ldap", "tacplus", "kerberos", "saml"}

ROLE_LABELS = {
    "superuser":    "Super User (acceso total)",
    "superreader":  "Super Reader (solo lectura)",
    "deviceadmin":  "Device Administrator",
    "devicereader": "Device Reader (solo lectura)",
    "custom":       "Rol personalizado",
    "unknown":      "Rol desconocido",
}


# ---------------------------------------------------------------------------
# Helpers de API y debug
# ---------------------------------------------------------------------------

def _debug(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    DEBUG_LINES.append(f"[{ts}] {msg}")


def _api_get(params: dict, timeout: int = TIMEOUT_PANORAMA, label: str = "") -> ET.Element:
    """Llamada a la API XML de Panorama. Lanza RuntimeError si no es success."""
    call_params = dict(params)
    call_params["key"] = PAN_API_KEY
    _debug(f"API GET  label={label!r}  params={_safe_params(call_params)}")
    try:
        resp = requests.get(
            f"{PAN_URL}/api/",
            params=call_params,
            verify=False,
            timeout=timeout,
        )
        resp.raise_for_status()
    except requests.exceptions.Timeout:
        raise RuntimeError("Timeout al conectar con Panorama")
    except requests.RequestException as exc:
        raise RuntimeError(f"Error de conexión: {exc}")
    _debug(f"  HTTP {resp.status_code}  len={len(resp.text)}")
    _debug(f"  BODY: {resp.text[:600]}")
    root = ET.fromstring(resp.text)
    status = root.attrib.get("status", "")
    if status != "success":
        msg = root.findtext(".//msg") or resp.text[:200]
        raise RuntimeError(f"status='{status}': {msg}")
    return root


def _safe_params(p: dict) -> str:
    return str({k: ("***" if k == "key" else v) for k, v in p.items()})


def _proxy_get(xpath: str, serial: str, label: str = "") -> ET.Element | None:
    """Config GET en el firewall via Panorama como proxy. Devuelve None si vacío o error."""
    try:
        root = _api_get(
            {"type": "config", "action": "get", "xpath": xpath, "target": serial},
            timeout=TIMEOUT_DEVICE,
            label=label or xpath[:60],
        )
        if root.attrib.get("code") == "7":
            return None
        return root
    except RuntimeError as exc:
        _debug(f"  [WARN] ({serial}) {label}: {exc}")
        return None


def _has_entries(root: ET.Element | None) -> bool:
    """Comprueba si el resultado XML tiene al menos una entry."""
    if root is None:
        return False
    return len(root.findall(".//entry")) > 0


def _auth_origin(method: str) -> str:
    if not method:
        return "LOCAL"
    m = method.lower()
    if m in EXTERNAL_AUTH_METHODS:
        return f"EXTERNO ({method.upper()})"
    return "LOCAL"


# ---------------------------------------------------------------------------
# Resolución de templates (mantenida para compatibilidad, ya no itera)
# ---------------------------------------------------------------------------

def _get_template_names_for_device(dev: dict) -> list[str]:
    """Devuelve templates del dispositivo (cacheado). Solo se usa en get_aaa_servers."""
    if "_tpl_cache" in dev:
        return dev["_tpl_cache"]
    templates: list[str] = list(dev.get("templates", []))
    for stack_name in dev.get("stacks", []):
        xpath = (
            f"/config/devices/entry[@name='localhost.localdomain']"
            f"/template-stack/entry[@name='{stack_name}']/templates/member"
        )
        root = _panorama_get(xpath, f"stack-members-{stack_name}")
        if root is not None:
            for m in root.findall(".//member"):
                if m.text and m.text not in templates:
                    templates.append(m.text)
    dev["_tpl_cache"] = templates
    return templates



# ---------------------------------------------------------------------------
# Acceso a config via target= (2 llamadas por dispositivo, todo cacheado)
# ---------------------------------------------------------------------------
# Usando target=<serial>, Panorama actúa como proxy y devuelve la config
# COMPLETAMENTE MERGEADA (local + templates + shared aplicados).
# No necesitamos saber si la config viene del template, shared o config local.
# Dos llamadas cubren todo:
#   1. /config/devices/entry[...]  → vsys, deviceconfig, server-profile local
#   2. /config/shared              → auth-profiles, admin-roles, server-profiles
#                                     y cualquier cosa en shared del Panorama

def _get_merged_config(serial: str, dev: dict) -> ET.Element | None:
    """
    Config de /config/devices/entry[...] via proxy. Cacheada.
    IMPORTANTE: el XML de respuesta tiene la forma
      <response><result><entry name="localhost.localdomain">...</entry></result></response>
    así que extraemos y cacheamos el nodo <entry name="localhost.localdomain">
    (no el <response> completo), para que las búsquedas relativas
    ("vsys/entry[...]/...", "server-profile/radius/entry", etc.) funcionen.
    """
    if "_cfg_cache" in dev:
        return dev["_cfg_cache"]
    root = _proxy_get(
        "/config/devices/entry[@name='localhost.localdomain']",
        serial, "merged-config"
    )
    device_root = None
    if root is not None:
        device_root = root.find(".//entry[@name='localhost.localdomain']")
    dev["_cfg_cache"] = device_root
    return device_root


def _get_shared_config(serial: str, dev: dict) -> ET.Element | None:
    """
    Config de /config/shared via proxy. Cacheada.
    IMPORTANTE: el XML de respuesta tiene la forma
      <response><result><shared>...</shared></result></response>
    así que extraemos y cacheamos el nodo <shared> (no el <response> completo).
    """
    if "_shared_cache" in dev:
        return dev["_shared_cache"]
    root = _proxy_get("/config/shared", serial, "shared-config")
    shared_root = None
    if root is not None:
        shared_root = root.find(".//shared")
    dev["_shared_cache"] = shared_root
    return shared_root


def _find_in_merged(serial: str, dev: dict, xpath_within_device: str) -> list[ET.Element]:
    """
    Busca elementos usando SOLO las 2 llamadas cacheadas (target=serial).
    Panorama resuelve templates + shared automáticamente.

    xpath_within_device: ruta relativa a /config/devices/entry[...]
    Ej: "vsys/entry[@name='vsys1']/authentication-profile/entry"
         "server-profile/radius/entry"
         "deviceconfig/system/permitted-ip/entry"
    """
    xpath = xpath_within_device.lstrip("/")

    # 1. Config del dispositivo (vsys, deviceconfig, server-profile local, etc.)
    cfg = _get_merged_config(serial, dev)
    if cfg is not None:
        results = cfg.findall(xpath)
        if results:
            return results

    # 2. /config/shared (auth-profiles, admin-roles, server-profiles globales)
    #    Eliminar segmentos que no existen en shared
    shared_xpath = xpath
    for frag in ("vsys/entry[@name='vsys1']/", "vsys/entry/",
                 "deviceconfig/system/"):
        shared_xpath = shared_xpath.replace(frag, "")

    shared = _get_shared_config(serial, dev)
    if shared is not None:
        results = shared.findall(shared_xpath)
        if results:
            return results

    return []


# _panorama_get se mantiene solo para las llamadas de inicialización
# (device-group-map, templates, template-stacks) que van a Panorama directamente
def _panorama_get(xpath: str, label: str = "") -> ET.Element | None:
    """Config GET directo en Panorama (sin proxy). Solo para inicialización."""
    try:
        root = _api_get(
            {"type": "config", "action": "get", "xpath": xpath},
            timeout=TIMEOUT_PANORAMA,
            label=label or xpath[:60],
        )
        if root.attrib.get("code") == "7":
            return None
        return root
    except RuntimeError as exc:
        _debug(f"  [WARN] Panorama {label}: {exc}")
        return None


def _proxy_get_with_tpl_fallback(
    xpath_suffix: str,
    serial: str,
    dev: dict,
    label: str = "",
) -> ET.Element | None:
    """
    Wrapper de compatibilidad. Usa _find_in_merged (una sola llamada al FW)
    en lugar de buscar template por template.
    """
    entries = _find_in_merged(serial, dev, xpath_suffix)
    if entries:
        wrapper = ET.Element("result")
        for e in entries:
            wrapper.append(e)
        return wrapper
    return None


def _proxy_get_shared_with_tpl_fallback(
    shared_xpath: str,
    serial: str,
    dev: dict,
    label: str = "",
) -> ET.Element | None:
    """Wrapper de compatibilidad. Usa _find_in_merged internamente."""
    suffix = shared_xpath.replace("/config/shared", "").replace("/config", "")
    entries = _find_in_merged(serial, dev, suffix)
    if entries:
        wrapper = ET.Element("result")
        for e in entries:
            wrapper.append(e)
        return wrapper
    return None



# ---------------------------------------------------------------------------
# Obtención y filtrado de dispositivos
# ---------------------------------------------------------------------------

def get_device_group_map() -> dict[str, list[str]]:
    xpath = (
        "/config/devices/entry[@name='localhost.localdomain']"
        "/device-group/entry"
    )
    serial_to_dgs: dict[str, list[str]] = {}
    try:
        root = _api_get(
            {"type": "config", "action": "get", "xpath": xpath},
            label="device-group-map",
        )
        for dg_entry in root.findall("entry"):
            dg_name = dg_entry.get("name", "")
            if not dg_name:
                continue
            # Usar "devices/entry" (hijos directos), NO ".//devices/entry".
            # El XML de Panorama anida vsys como <entry> dentro del nodo del
            # dispositivo; con // se encontrarían esos vsys como si fueran
            # dispositivos adicionales, repitiendo el DG N veces (una por vsys).
            for dev_entry in dg_entry.findall("devices/entry"):
                serial = dev_entry.get("name", "")
                if serial:
                    serial_to_dgs.setdefault(serial, []).append(dg_name)
    except RuntimeError as exc:
        print(f"  [WARN] No se pudo obtener device groups: {exc}")
    return serial_to_dgs


def get_panorama_templates() -> dict[str, list[str]]:
    """serial -> [template_name, ...]  (templates simples, no stacks)"""
    xpath = (
        "/config/devices/entry[@name='localhost.localdomain']"
        "/template/entry"
    )
    result: dict[str, list[str]] = {}
    try:
        root = _api_get(
            {"type": "config", "action": "get", "xpath": xpath},
            label="panorama-templates",
        )
        for entry in root.findall(".//entry"):
            tpl_name = entry.get("name", "")
            for dev in entry.findall(".//devices/entry"):
                serial = dev.get("name", "")
                if serial:
                    result.setdefault(serial, []).append(tpl_name)
    except RuntimeError as exc:
        _debug(f"templates: {exc}")
    return result


def get_panorama_template_stacks() -> dict[str, list[str]]:
    """serial -> [stack_name, ...]"""
    xpath = (
        "/config/devices/entry[@name='localhost.localdomain']"
        "/template-stack/entry"
    )
    result: dict[str, list[str]] = {}
    try:
        root = _api_get(
            {"type": "config", "action": "get", "xpath": xpath},
            label="panorama-template-stacks",
        )
        for entry in root.findall(".//entry"):
            stk_name = entry.get("name", "")
            for dev in entry.findall(".//devices/entry"):
                serial = dev.get("name", "")
                if serial:
                    result.setdefault(serial, []).append(stk_name)
    except RuntimeError as exc:
        _debug(f"template-stacks: {exc}")
    return result


def get_connected_devices() -> list[dict]:
    print("[INFO] Consultando dispositivos conectados a Panorama...")
    root = _api_get(
        {"type": "op", "cmd": "<show><devices><connected/></devices></show>"},
        label="show-devices-connected",
    )
    dg_map  = get_device_group_map()
    tpl_map = get_panorama_templates()
    stk_map = get_panorama_template_stacks()

    devices = []
    for entry in root.findall(".//devices/entry"):
        serial  = entry.findtext("serial") or entry.get("name", "")
        name    = entry.findtext("hostname") or entry.findtext("devicename") or ""
        ip      = entry.findtext("ip-address") or ""
        model   = entry.findtext("model") or ""
        sw_ver  = entry.findtext("sw-version") or ""
        dg_list = dg_map.get(serial) or []
        devices.append({
            "serial":     serial,
            "name":       name,
            "ip":         ip,
            "model":      model,
            "sw_version": sw_ver,
            "dg_list":    dg_list,
            "templates":  tpl_map.get(serial, []),
            "stacks":     stk_map.get(serial, []),
        })

    print(f"[INFO] {len(devices)} dispositivo(s) encontrado(s).")
    return devices


def filter_devices(devices: list[dict], args: argparse.Namespace) -> list[dict]:
    if args.sn:
        f = [d for d in devices if d["serial"].upper() == args.sn.upper()]
        if not f:
            sys.exit(f"[ERROR] Serial no encontrado: {args.sn}")
        return f
    if args.device_name:
        f = [d for d in devices if d["name"].lower() == args.device_name.lower()]
        if not f:
            sys.exit(f"[ERROR] Nombre no encontrado: {args.device_name}")
        return f
    if args.device_group:
        f = [
            d for d in devices
            if any(dg.lower() == args.device_group.lower() for dg in d["dg_list"])
        ]
        if not f:
            sys.exit(f"[ERROR] Device group no encontrado: {args.device_group}")
        return f
    return devices


# ---------------------------------------------------------------------------
# Sección 3 — Auth Profiles (se obtiene primero para cruzar con admins)
# ---------------------------------------------------------------------------

def get_auth_profiles(serial: str, dev: dict) -> list[dict]:
    """
    Auth profiles con tipo LOCAL/EXTERNO, IP del servidor, y lista de usuarios
    autenticados por ese perfil (se rellena en post-proceso al cruzar con admins).
    Busca en vsys1, shared, y templates si la config viene de plantilla.
    """
    # 1. vsys1 local → template fallback
    root = _proxy_get_with_tpl_fallback(
        "/vsys/entry[@name='vsys1']/authentication-profile/entry",
        serial, dev, "auth-profiles-vsys"
    )
    # 2. shared → template fallback
    if not _has_entries(root):
        root = _proxy_get_shared_with_tpl_fallback(
            "/config/shared/authentication-profile/entry",
            serial, dev, "auth-profiles"
        )
    if not _has_entries(root):
        return []

    profiles = []
    for entry in root.findall(".//entry"):
        name       = entry.get("name", "")
        method_el  = entry.find("method")
        method     = ""
        server_prof = ""
        if method_el is not None:
            for child in method_el:
                method      = child.tag
                server_prof = child.findtext("server-profile") or ""
                break

        mfa_factors = [
            f.get("name", "")
            for f in entry.findall(".//multi-factor/factors/entry")
        ]
        allow_list = [
            m.text or ""
            for m in entry.findall(".//allow-list/member")
        ]

        profiles.append({
            "profile_name":   name,
            "method":         method,
            "auth_origin":    _auth_origin(method),
            "server_profile": server_prof,
            "mfa_factors":    "; ".join(mfa_factors),
            "allow_list":     "; ".join(allow_list),
            "server_ip":      "",      # se rellena en get_aaa_servers
            "users":          [],      # se rellena en post-proceso
        })
    return profiles


# ---------------------------------------------------------------------------
# Sección 8 — Servidores AAA (nombres e IPs)
# ---------------------------------------------------------------------------

AAA_XPATHS = {
    "radius":   "/server-profile/radius/entry",
    "ldap":     "/server-profile/ldap/entry",
    "tacplus":  "/server-profile/tacplus/entry",
    "kerberos": "/server-profile/kerberos/entry",
}


def _collect_aaa_entries(root: ET.Element, proto: str) -> list[dict]:
    """
    Extrae servidores de un resultado XML de server-profile AAA.
    En RADIUS el campo IP puede ser <ip-address> o <server>; se prueba ambos.

    IMPORTANTE: se usa root.findall("entry") (hijos DIRECTOS), no ".//entry".
    Un profile como RADIUS_DG_Shared contiene servidores anidados en
    server/entry (server1, server2) — con ".//entry" esos servidores
    anidados se contaban erróneamente como profiles independientes,
    duplicando resultados (1 profile real -> aparecía como 3 "profiles").
    """
    results = []
    for profile in root.findall("entry"):
        prof_name   = profile.get("name", "")
        srv_entries = profile.findall("./server/entry")
        if srv_entries:
            for srv in srv_entries:
                # RADIUS usa <ip-address>, LDAP/TACACS+ usan <server>
                ip = (srv.findtext("ip-address")
                      or srv.findtext("server")
                      or srv.get("name", ""))
                results.append({
                    "proto":       proto,
                    "profile":     prof_name,
                    "server_name": srv.get("name", ""),
                    "server_ip":   ip,
                    "port":        srv.findtext("port") or "",
                    "timeout":     profile.findtext("timeout") or "",
                })
        else:
            ip = (profile.findtext("ip-address")
                  or profile.findtext("server")
                  or "")
            results.append({
                "proto":       proto,
                "profile":     prof_name,
                "server_name": prof_name,
                "server_ip":   ip,
                "port":        profile.findtext("port") or "",
                "timeout":     profile.findtext("timeout") or "",
            })
    return results


def get_aaa_servers(serial: str, dev: dict) -> list[dict]:
    """
    Servidores AAA usando las 2 llamadas cacheadas (merged-config + shared-config).
    Panorama via target= ya resuelve templates y shared automáticamente.
    """
    servers:        list[dict] = []
    found_profiles: set[str]   = set()

    def _add(entries: list[dict]) -> bool:
        added = False
        for e in entries:
            key = f"{e['proto']}:{e['profile']}:{e['server_name']}:{e['server_ip']}"
            if key not in found_profiles:
                found_profiles.add(key)
                servers.append(e)
                added = True
        return added

    for proto, suffix in AAA_XPATHS.items():
        # suffix = "/server-profile/<proto>/entry"
        # Buscar en la config mergeada del dispositivo (incluye templates)
        entries = _find_in_merged(serial, dev, suffix.lstrip("/"))
        if entries:
            # Envolver para reutilizar _collect_aaa_entries
            wrapper = ET.Element("result")
            for e in entries:
                wrapper.append(e)
            _add(_collect_aaa_entries(wrapper, proto))

    return servers


def _enrich_auth_profiles_with_servers(
    auth_profiles: list[dict],
    aaa_servers: list[dict],
) -> None:
    """
    Rellena el campo server_ip en cada auth profile cruzando con los
    servidores AAA por nombre de profile.
    """
    # Mapa profile_name -> lista de "nombre (IP:puerto)"
    prof_to_servers: dict[str, list[str]] = {}
    for srv in aaa_servers:
        entry = srv["server_name"]
        if srv["server_ip"]:
            entry += f" ({srv['server_ip']}"
            if srv["port"]:
                entry += f":{srv['port']}"
            entry += ")"
        prof_to_servers.setdefault(srv["profile"], []).append(entry)

    for ap in auth_profiles:
        sp = ap.get("server_profile", "")
        if sp and sp in prof_to_servers:
            ap["server_ip"] = "; ".join(prof_to_servers[sp])


def _enrich_auth_profiles_with_users(
    auth_profiles: list[dict],
    admins: list[dict],
) -> None:
    """
    Rellena el campo users en cada auth profile con los admins que lo usan.
    Usa el campo authentication-profile del propio entry del admin (fuente
    de verdad) en lugar de inferirlo por allow-list.
    """
    prof_map: dict[str, list[str]] = {ap["profile_name"]: [] for ap in auth_profiles}
    for adm in admins:
        prof = adm.get("auth_profile_name", "")
        if prof and prof in prof_map:
            prof_map[prof].append(adm["username"])
    for ap in auth_profiles:
        ap["users"] = prof_map.get(ap["profile_name"], [])


# ---------------------------------------------------------------------------
# Sección 1 — Administradores locales
# ---------------------------------------------------------------------------

def get_admins(serial: str, dev: dict, auth_profiles: list[dict]) -> list[dict]:
    """
    Admins locales. Determina si es LOCAL o REMOTO leyendo el campo
    <authentication-profile> del propio entry XML del admin — campo explícito
    en PAN-OS que indica qué perfil usa ese usuario concreto.
    Si no tiene ese campo, es autenticación LOCAL.
    """
    root = _proxy_get("/config/mgt-config/users/entry", serial, "admins")
    if not _has_entries(root):
        return []

    # Mapa profile_name -> auth_profile dict para cruce rápido
    prof_map: dict[str, dict] = {ap["profile_name"]: ap for ap in auth_profiles}

    admins = []
    for entry in root.findall(".//entry"):
        username  = entry.get("name", "")
        role_type = ""
        role_name = ""

        permissions = entry.find("permissions")
        if permissions is not None:
            role_elem = permissions.find("role-based")
            if role_elem is not None:
                custom = role_elem.find("custom")
                if custom is not None:
                    role_type = "custom"
                    role_name = custom.findtext("profile") or ""
                else:
                    for child in role_elem:
                        role_type = child.tag
                        break
            else:
                for child in permissions:
                    role_type = child.tag
                    break

        if not role_type:
            for tag in ("superuser", "superreader", "deviceadmin", "devicereader"):
                if entry.find(tag) is not None:
                    role_type = tag
                    break

        # Estado de cuenta
        disabled       = (entry.findtext("disabled") or "no").lower()
        failed_str     = entry.findtext("failed-attempts") or "0"
        lockout        = entry.findtext("lockout") or ""
        is_locked      = bool(lockout) or (failed_str not in ("0", ""))
        if disabled in ("yes", "true", "1"):
            account_status = "DESHABILITADO"
        elif is_locked:
            account_status = "BLOQUEADO"
        else:
            account_status = "ACTIVO"

        # Tipo de autenticación: leer campo authentication-profile del admin
        # Este campo es explícito: si está presente → REMOTO con ese perfil
        # Si no está presente → LOCAL (password local del firewall)
        auth_profile_name = entry.findtext("authentication-profile") or ""
        if auth_profile_name and auth_profile_name in prof_map:
            ap        = prof_map[auth_profile_name]
            auth_type = f"REMOTO ({ap['method'].upper()})"
            auth_srv  = ap.get("server_ip") or ap.get("server_profile") or ""
        elif auth_profile_name:
            # Tiene perfil asignado pero no lo hemos cargado (raro)
            auth_type = f"REMOTO (perfil: {auth_profile_name})"
            auth_srv  = ""
        else:
            auth_type = "LOCAL"
            auth_srv  = ""
            # auth_profile_name ya es ""

        # Política de password: leer campo password-profile del admin
        pw_profile = entry.findtext("password-profile") or ""

        admins.append({
            "username":           username,
            "role_type":          role_type or "unknown",
            "role_name":          role_name,
            "account_status":     account_status,
            "disabled":           disabled,
            "failed_attempts":    failed_str,
            "locked":             "SÍ" if is_locked else "NO",
            "auth_type":          auth_type,
            "auth_server":        auth_srv,
            "auth_profile_name":  auth_profile_name,
            "pw_profile":         pw_profile,  # perfil explícito de password si lo tiene
        })
    return admins


# ---------------------------------------------------------------------------
# Sección 2 — Roles personalizados + usuarios que los tienen
# ---------------------------------------------------------------------------

def get_custom_roles(serial: str, dev: dict, admins: list[dict]) -> list[dict]:
    """
    Roles personalizados del firewall. Para cada rol indica qué admin lo usa.
    Busca también en templates si no hay config local.
    """
    root = _proxy_get_with_tpl_fallback(
        "/vsys/entry[@name='vsys1']/admin-role/entry",
        serial, dev, "custom-roles"
    )
    if not _has_entries(root):
        return []

    # Mapa perfil -> lista de usuarios
    profile_to_users: dict[str, list[str]] = {}
    for adm in admins:
        if adm["role_type"] == "custom" and adm["role_name"]:
            profile_to_users.setdefault(adm["role_name"], []).append(adm["username"])

    roles = []
    for entry in root.findall(".//entry"):
        role_name  = entry.get("name", "")
        vsys_scope = [
            v.text or ""
            for v in entry.findall(".//vsys/member")
        ]
        scope_str = "; ".join(vsys_scope) if vsys_scope else "global"
        users_str = ", ".join(profile_to_users.get(role_name, [])) or "(ninguno)"

        roles.append({
            "role_name":  role_name,
            "vsys_scope": scope_str,
            "used_by":    users_str,
        })
    return roles


# ---------------------------------------------------------------------------
# Sección 4 — Política de contraseñas
# ---------------------------------------------------------------------------

def get_password_policy(serial: str) -> dict:
    root = _proxy_get("/config/mgt-config/password-complexity", serial, "password-policy")
    if root is None:
        return {}
    el = root.find(".//password-complexity")
    if el is None:
        el = root

    def _t(tag: str) -> str:
        return el.findtext(tag) or ""

    return {
        "enabled":            _t("enabled"),
        "minimum_length":     _t("minimum-length"),
        "minimum_uppercase":  _t("minimum-uppercase-letters"),
        "minimum_lowercase":  _t("minimum-lowercase-letters"),
        "minimum_numeric":    _t("minimum-numeric-letters"),
        "minimum_special":    _t("minimum-special-chars"),
        "block_repeated":     _t("block-repeated-characters"),
        "block_username":     _t("block-username-inclusion"),
        "password_change":    _t("password-change"),
        "expiration_period":  _t("expiration-period"),
        "expiration_warning": _t("expiration-warning-period"),
        "lockout_time":       _t("lockout-time"),
        "failed_attempts":    _t("failed-attempts"),
    }


# ---------------------------------------------------------------------------
# Sección 5 — Authentication Sequences
# ---------------------------------------------------------------------------

def get_auth_sequences(serial: str, dev: dict) -> list[dict]:
    # _proxy_get_with_tpl_fallback ya incluye fallback a shared (niveles 3 y 4)
    # — no hace falta una segunda llamada a _proxy_get_shared_with_tpl_fallback
    root = _proxy_get_with_tpl_fallback(
        "/vsys/entry[@name='vsys1']/authentication-sequence/entry",
        serial, dev, "auth-sequences"
    )
    if not _has_entries(root):
        return []

    sequences = []
    for entry in root.findall(".//entry"):
        profiles = [
            m.text or ""
            for m in entry.findall(".//authentication-profiles/member")
        ]
        sequences.append({
            "seq_name":   entry.get("name", ""),
            "profiles":   "; ".join(profiles),
            "use_domain": entry.findtext("use-userid-domain") or "",
        })
    return sequences


# ---------------------------------------------------------------------------
# Sección 6 — Usuarios y grupos locales
# ---------------------------------------------------------------------------

def get_local_users(serial: str) -> list[dict]:
    root = _proxy_get(
        "/config/devices/entry[@name='localhost.localdomain']"
        "/vsys/entry[@name='vsys1']/local-user-database/user/entry",
        serial, "local-users"
    )
    if root is None:
        return []
    return [
        {
            "type":     "user",
            "name":     e.get("name", ""),
            "member":   "",
            "disabled": e.findtext("disabled") or "no",
        }
        for e in root.findall(".//entry")
    ]


def get_local_groups(serial: str) -> list[dict]:
    root = _proxy_get(
        "/config/devices/entry[@name='localhost.localdomain']"
        "/vsys/entry[@name='vsys1']/local-user-database/user-group/entry",
        serial, "local-groups"
    )
    if root is None:
        return []
    groups = []
    for entry in root.findall(".//entry"):
        members = [m.text or "" for m in entry.findall(".//user/member")]
        groups.append({
            "type":     "group",
            "name":     entry.get("name", ""),
            "member":   "; ".join(members),
            "disabled": "",
        })
    return groups


def build_user_group_membership(
    local_users: list[dict], local_groups: list[dict]
) -> dict[str, list[str]]:
    membership: dict[str, list[str]] = {u["name"]: [] for u in local_users}
    for g in local_groups:
        for m in g["member"].split("; "):
            uname = m.strip()
            if uname:
                membership.setdefault(uname, []).append(g["name"])
    return membership


# ---------------------------------------------------------------------------
# Sección 7 — Vsys reales y admins con acceso
# ---------------------------------------------------------------------------

def get_vsys_access(serial: str, admins: list[dict]) -> list[dict]:
    """
    Lista los vsys REALES del dispositivo (no las zonas).
    En PAN-OS la config del dispositivo tiene vsys/entry, y cada vsys
    contiene zone/entry. Este método devuelve solo los vsys, no las zonas.
    """
    # Consultar vsys via op command — devuelve vsys reales, no zonas
    root = _op_proxy(
        "<show><system><info/></system></show>",
        serial, "system-info"
    )
    # Intentar obtener vsys del sistema via op
    vsys_root = _op_proxy(
        "<show><vsys/></show>",
        serial, "show-vsys"
    )

    vsys_names = []
    if vsys_root is not None:
        # El comando show vsys devuelve los vsys del dispositivo
        for entry in vsys_root.findall(".//entry"):
            vname = entry.get("name") or entry.findtext("name") or ""
            if vname:
                vsys_names.append(vname)

    # Fallback: leer de config pero solo el nivel vsys/entry, no zonas
    if not vsys_names:
        cfg_root = _proxy_get(
            "/config/devices/entry[@name='localhost.localdomain']/vsys/entry",
            serial, "vsys-cfg"
        )
        if cfg_root is not None:
            # Cada entry aquí es un vsys; su nombre (no sus hijos) es el vsys
            for entry in cfg_root.findall("result/entry"):
                vname = entry.get("name", "")
                if vname:
                    vsys_names.append(vname)
            # Si el resultado viene aplanado
            if not vsys_names:
                for entry in cfg_root.findall(".//entry"):
                    # Evitar zonas: los vsys están al primer nivel de result
                    vname = entry.get("name", "")
                    # Las zonas son hijos de vsys, no vsys en sí
                    # Si el entry tiene un tag padre "vsys" en el xpath, es un vsys
                    if vname and entry.tag == "entry":
                        vsys_names.append(vname)
                        break  # solo coger el primero para evitar zonas

    # Si solo tenemos vsys1 (lo más común en firewalls con un vsys)
    if not vsys_names:
        vsys_names = ["vsys1"]

    # Construir info de acceso por vsys
    items = []
    for vsys in vsys_names:
        # Admins con scope explícito a este vsys, o globales
        admins_info = []
        for adm in admins:
            admins_info.append(f"{adm['username']} (global)")
        items.append({
            "vsys":   vsys,
            "admins": "; ".join(admins_info),
        })
    return items


def _op_proxy(cmd: str, serial: str, label: str = "") -> ET.Element | None:
    try:
        return _api_get(
            {"type": "op", "cmd": cmd, "target": serial},
            timeout=TIMEOUT_DEVICE,
            label=label or cmd[:60],
        )
    except RuntimeError as exc:
        _debug(f"  [WARN] op ({serial}) {label}: {exc}")
        return None


# ---------------------------------------------------------------------------
# Sección 9 — Group Mapping
# ---------------------------------------------------------------------------

def get_group_mapping(serial: str, dev: dict) -> list[dict]:
    root = _proxy_get_with_tpl_fallback(
        "/vsys/entry[@name='vsys1']/user-id-collector/group-mapping/entry",
        serial, dev, "group-mapping"
    )
    if not _has_entries(root):
        return []

    mappings = []
    for entry in root.findall(".//entry"):
        groups_inc = [g.text or "" for g in entry.findall(".//group-include-list/member")]
        groups_exc = [g.text or "" for g in entry.findall(".//group-exclude-list/member")]
        mappings.append({
            "mapping_name":    entry.get("name", ""),
            "server_profile":  entry.findtext("server-profile") or "",
            "domain":          entry.findtext("domain") or "",
            "groups_included": "; ".join(groups_inc) if groups_inc else "(todos)",
            "groups_excluded": "; ".join(groups_exc) if groups_exc else "(ninguno)",
        })
    return mappings


# ---------------------------------------------------------------------------
# Sección 12 — Log Forwarding Profiles + Device Log Settings
# ---------------------------------------------------------------------------

def get_log_forwarding_profiles(serial: str, dev: dict) -> list[dict]:
    """Objects > Log Forwarding Profiles."""
    root = _proxy_get_with_tpl_fallback(
        "/vsys/entry[@name='vsys1']/log-forwarding-profile/entry",
        serial, dev, "log-forwarding"
    )
    if not _has_entries(root):
        return []

    profiles = []
    for entry in root.findall(".//entry"):
        match_list = []
        for ml in entry.findall(".//match-list/entry"):
            log_type = ml.findtext("log-type") or ""
            dests = []
            for sl in ml.findall(".//send-syslog/using-syslog-setting/entry"):
                dests.append(f"syslog:{sl.get('name','')}")
            for em in ml.findall(".//send-email/using-email-setting/entry"):
                dests.append(f"email:{em.get('name','')}")
            for ht in ml.findall(".//send-http/using-http-setting/entry"):
                dests.append(f"http:{ht.get('name','')}")
            for sn in ml.findall(".//send-snmptrap/using-snmptrap-setting/entry"):
                dests.append(f"snmp:{sn.get('name','')}")
            match_list.append({
                "name":         ml.get("name", ""),
                "log_type":     log_type,
                "destinations": ", ".join(dests) if dests else "(sin destino)",
                "is_audit":     log_type.lower() in ("system", "config", "audit"),
            })
        profiles.append({
            "profile_name": entry.get("name", ""),
            "description":  entry.findtext("description") or "",
            "match_list":   match_list,
        })
    return profiles


def get_device_log_settings(serial: str, dev: dict) -> dict:
    """
    Device > Log Settings: destinos de System log y Config log.
    El XML real de PAN-OS usa:
      <send-syslog><member>nombre_perfil_syslog</member></send-syslog>
      <send-to-panorama>yes</send-to-panorama>
    (NO usa <send-syslog><using-syslog-setting><entry> como Log Forwarding Profiles)
    """
    result = {
        "panorama":        False,
        "syslog_profiles": [],
        "system_entries":  [],
        "config_entries":  [],
    }

    for log_type in ("system", "config"):
        root = _proxy_get_with_tpl_fallback(
            f"/deviceconfig/system/log-settings/{log_type}",
            serial, dev, f"log-settings-{log_type}"
        )
        if not _has_entries(root):
            root = _proxy_get_with_tpl_fallback(
                f"/vsys/entry[@name='vsys1']/log-settings/{log_type}",
                serial, dev, f"log-settings-vsys-{log_type}"
            )
        if root is None:
            continue

        for match in root.findall(".//match-list/entry"):
            entry_name = match.get("name", "")

            # send-syslog puede tener <member> (Device Log Settings)
            # o <using-syslog-setting><entry> (Log Forwarding Profiles)
            syslog_members = [
                m.text or ""
                for m in match.findall("send-syslog/member")
                if m.text
            ]
            # También intentar la forma de entry por compatibilidad
            syslog_entries = [
                e.get("name", "")
                for e in match.findall(".//send-syslog/using-syslog-setting/entry")
            ]
            syslog_dests = syslog_members or syslog_entries

            # send-to-panorama puede ser un elemento vacío o con texto "yes"
            pan_el = match.find("send-to-panorama")
            to_panorama = pan_el is not None and pan_el.text not in ("no", "false", "0", None) or pan_el is not None and pan_el.text is None

            info = {
                "log_type": log_type,
                "name":     entry_name,
                "panorama": to_panorama,
                "syslog":   "; ".join(syslog_dests) if syslog_dests else "",
            }
            if log_type == "system":
                result["system_entries"].append(info)
            else:
                result["config_entries"].append(info)
            if to_panorama:
                result["panorama"] = True
            result["syslog_profiles"].extend(syslog_dests)

    return result


# ---------------------------------------------------------------------------
# Sección 13 — Syslog Servers
# ---------------------------------------------------------------------------

def get_syslog_servers(serial: str, dev: dict) -> list[dict]:
    """
    Servidores syslog. Busca en vsys, device y templates.
    En PAN-OS los syslog server profiles están bajo:
      /config/devices/.../vsys/entry/log-settings/syslog  (vsys scope)
      /config/devices/.../log-settings/syslog             (device scope)
    """
    servers = []

    for label, xpath_suffix in [
        ("syslog-vsys",   "/vsys/entry[@name='vsys1']/log-settings/syslog/entry"),
        ("syslog-device", "/deviceconfig/system/log-settings/syslog/entry"),
    ]:
        root = _proxy_get_with_tpl_fallback(xpath_suffix, serial, dev, label)
        if not _has_entries(root):
            continue
        for profile in root.findall(".//entry"):
            prof_name = profile.get("name", "")
            for srv in profile.findall(".//server/entry"):
                servers.append({
                    "syslog_profile": prof_name,
                    "server_name":    srv.get("name", ""),
                    "server_addr":    srv.findtext("server") or "",
                    "transport":      srv.findtext("transport") or "UDP",
                    "port":           srv.findtext("port") or "514",
                    "format":         srv.findtext("format") or "BSD",
                    "facility":       srv.findtext("facility") or "",
                })
        if servers:
            break  # Encontrado en este scope, no seguir buscando

    return servers


# ---------------------------------------------------------------------------
# Sección 15 — Fuentes de gestión permitidas
# ---------------------------------------------------------------------------

def get_permitted_ips(serial: str, dev: dict) -> list[str]:
    """
    IPs permitidas para gestión. Suele venir del template (src="tpl").
    Busca la IP en el nombre del entry porque el XML usa entry/@name para las IPs.
    """
    root = _proxy_get_with_tpl_fallback(
        "/deviceconfig/system/permitted-ip",
        serial, dev, "permitted-ips"
    )
    if root is None:
        return []

    ips = []
    # Las IPs pueden venir como entry/@name o como <member> text
    for entry in root.findall(".//entry"):
        name = entry.get("name", "")
        if name:
            ips.append(name)
    for member in root.findall(".//member"):
        if member.text:
            ips.append(member.text)

    return list(dict.fromkeys(ips))  # deduplicar manteniendo orden


# ---------------------------------------------------------------------------
# Recolección completa por dispositivo
# ---------------------------------------------------------------------------

def collect_device_data(dev: dict) -> dict:
    """
    Recopila todas las secciones para un dispositivo.
    Las secciones independientes se ejecutan en paralelo con ThreadPoolExecutor
    para reducir el tiempo total (de ~70s a ~15s por dispositivo).

    Orden de dependencias:
      1. auth_profiles + aaa_servers  → deben ir primero (admins depende de ellos)
      2. admins                       → depende de auth_profiles
      3. Todo lo demás                → independiente, se paraliza
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    serial = dev["serial"]
    name   = dev["name"] or serial
    print(f"  [INFO] -> {name} ({serial})")

    # Pre-calentar el caché de templates (1 llamada en lugar de N)
    _get_template_names_for_device(dev)

    # Pre-calentar merged-config y shared-config ANTES de paralelizar.
    # Si no se hace esto, dos hilos pueden ver "cache miss" simultáneamente
    # y disparar la misma llamada API dos veces (visto en debug: timestamps
    # idénticos para 'merged-config' y 'shared-config').
    _get_merged_config(serial, dev)
    _get_shared_config(serial, dev)

    # --- Fase 1: auth_profiles + aaa_servers en paralelo (se necesitan juntos) ---
    with ThreadPoolExecutor(max_workers=2) as ex:
        f_auth    = ex.submit(get_auth_profiles, serial, dev)
        f_aaa     = ex.submit(get_aaa_servers,   serial, dev)
    auth_profiles = f_auth.result()
    aaa_servers   = f_aaa.result()
    _enrich_auth_profiles_with_servers(auth_profiles, aaa_servers)

    # --- Fase 2: admins (depende de auth_profiles ya enriquecidos) ---
    admins = get_admins(serial, dev, auth_profiles)
    _enrich_auth_profiles_with_users(auth_profiles, admins)

    # --- Fase 3: todo lo demás en paralelo ---
    with ThreadPoolExecutor(max_workers=6) as ex:
        f_roles     = ex.submit(get_custom_roles,          serial, dev, admins)
        f_pw        = ex.submit(get_password_policy,       serial)
        f_seqs      = ex.submit(get_auth_sequences,        serial, dev)
        f_lusers    = ex.submit(get_local_users,           serial)
        f_lgroups   = ex.submit(get_local_groups,          serial)
        f_vsys      = ex.submit(get_vsys_access,           serial, admins)
        f_gmap      = ex.submit(get_group_mapping,         serial, dev)
        f_logfwd    = ex.submit(get_log_forwarding_profiles, serial, dev)
        f_devlog    = ex.submit(get_device_log_settings,  serial, dev)
        f_syslog    = ex.submit(get_syslog_servers,        serial, dev)
        f_permips   = ex.submit(get_permitted_ips,         serial, dev)

    local_users  = f_lusers.result()
    local_groups = f_lgroups.result()

    return {
        "device":            dev,
        "admins":            admins,
        "custom_roles":      f_roles.result(),
        "auth_profiles":     auth_profiles,
        "password_policy":   f_pw.result(),
        "auth_sequences":    f_seqs.result(),
        "local_users":       local_users,
        "local_groups":      local_groups,
        "user_group_membership": build_user_group_membership(local_users, local_groups),
        "vsys_access":       f_vsys.result(),
        "aaa_servers":       aaa_servers,
        "group_mapping":     f_gmap.result(),
        "log_forwarding":    f_logfwd.result(),
        "device_log":        f_devlog.result(),
        "syslog_servers":    f_syslog.result(),
        "permitted_ips":     f_permips.result(),
    }


# ---------------------------------------------------------------------------
# Selección interactiva de agrupación
# ---------------------------------------------------------------------------

GROUP_OPTIONS = {
    "1": "firewall", "2": "user", "3": "both",
    "firewall": "firewall", "user": "user", "both": "both",
}


# ---------------------------------------------------------------------------
# Vista 1 — Por Device Group / Firewall
# ---------------------------------------------------------------------------

def _hr(width: int = 70) -> str:
    return "-" * width


def _section(title: str) -> None:
    print(f"  |")
    print(f"  |  ── {title}")


def _pp_line(label: str, value: str, width: int = 22) -> None:
    v = value if value else "(no configurado)"
    print(f"  |    {label:<{width}}: {v}")


def print_by_firewall(results_by_dg: dict[str, list[dict]]) -> None:
    print()
    print("=" * 70)
    print("  AUDITORÍA — Vista por Device Group / Firewall")
    print("=" * 70)

    total_devs = total_items = 0

    for dg_name, results in results_by_dg.items():
        print()
        print(f"  ╔══ Device Group: {dg_name} ({len(results)} dispositivo(s))")

        for r in results:
            dev = r["device"]
            total_devs += 1
            dg_str  = ", ".join(dev["dg_list"]) if dev["dg_list"] else "-"
            pp      = r["password_policy"]
            pp_enabled = pp.get("enabled", "") == "yes"

            print(f"  ║")
            print(f"  ╠═ Dispositivo : {dev['name'] or '(sin nombre)'}")
            print(f"  |  Serial      : {dev['serial']}")
            print(f"  |  Modelo      : {dev['model']}   PAN-OS: {dev['sw_version']}")
            print(f"  |  IP gestión  : {dev['ip']}")
            print(f"  |  Device Group: {dg_str}")

            # --- 1. Admins ---
            _section("1. Administradores  (estado / rol / autenticación / política de password)")
            if not r["admins"]:
                print("  |    (ninguno o sin acceso)")
            else:
                for adm in r["admins"]:
                    rl = ROLE_LABELS.get(adm["role_type"], adm["role_type"])
                    if adm["role_name"]:
                        rl += f" -> perfil: '{adm['role_name']}'"
                    status_tag = f"[{adm['account_status']}]"
                    lock_info  = (
                        f"  intentos={adm['failed_attempts']}"
                        if adm["failed_attempts"] not in ("0", "") else ""
                    )
                    auth_info = adm["auth_type"]
                    if adm["auth_server"]:
                        auth_info += f" -> {adm['auth_server']}"

                    # Política de password: perfil explícito > política global > sin política
                    if adm.get("pw_profile"):
                        pw_info = f"perfil: '{adm['pw_profile']}'"
                    elif pp_enabled:
                        pw_info = f"política global (mín. {pp.get('minimum_length','?')} chars"
                        if pp.get("expiration_period"):
                            pw_info += f", expira {pp['expiration_period']}d"
                        pw_info += ")"
                    else:
                        pw_info = "sin política de password"

                    print(f"  |    * {adm['username']:<25} {status_tag:<15} {rl}")
                    print(f"  |      auth: {auth_info:<40} pwd: {pw_info}")
                    if lock_info:
                        print(f"  |      {lock_info.strip()}")
                    total_items += 1

            # --- 2. Roles personalizados ---
            _section("2. Roles personalizados  (usuarios que los tienen)")
            if not r["custom_roles"]:
                print("  |    (ninguno)")
            else:
                for ro in r["custom_roles"]:
                    print(f"  |    * {ro['role_name']}")
                    print(f"  |      scope: {ro['vsys_scope']}")
                    print(f"  |      usado por: {ro['used_by']}")
                    total_items += 1

            # --- 3. Auth Profiles ---
            _section("3. Perfiles de autenticación  (LOCAL vs EXTERNO / IP servidor / usuarios)")
            if not r["auth_profiles"]:
                # Indicar explícitamente que todos los admins usan autenticación local
                print("  |    [LOCAL]  Todos los administradores usan contraseña local del dispositivo")
            else:
                for ap in r["auth_profiles"]:
                    users_str = ", ".join(ap["users"]) if ap["users"] else "(no determinado)"
                    if ap["auth_origin"] == "LOCAL":
                        srv_str = "(base de datos local)"
                    else:
                        srv_str = ap.get("server_ip") or ap.get("server_profile") or "(sin servidor)"
                    print(f"  |    * {ap['profile_name']:<30} [{ap['auth_origin']}]")
                    if ap["auth_origin"] != "LOCAL":
                        print(f"  |      servidor: {srv_str}")
                    print(f"  |      usuarios autenticados: {users_str}")
                    if ap.get("mfa_factors"):
                        print(f"  |      MFA: {ap['mfa_factors']}")
                    total_items += 1
                # Admins sin perfil asignado → locales
                remote_users = {u for ap in r["auth_profiles"] for u in ap["users"]}
                local_admins = [a["username"] for a in r["admins"] if a["username"] not in remote_users]
                if local_admins:
                    print(f"  |    * [LOCAL]  sin perfil asignado: {', '.join(local_admins)}")

            # --- 4. Política de contraseñas ---
            _section("4. Política de contraseñas  (global del dispositivo)")
            if not pp:
                print("  |    (sin configuración o sin acceso)")
            else:
                _pp_line("Habilitada",       pp.get("enabled",""))
                _pp_line("Long. mínima",     pp.get("minimum_length",""))
                _pp_line("Mayúsculas mín.",  pp.get("minimum_uppercase",""))
                _pp_line("Minúsculas mín.",  pp.get("minimum_lowercase",""))
                _pp_line("Números mín.",     pp.get("minimum_numeric",""))
                _pp_line("Especiales mín.",  pp.get("minimum_special",""))
                _pp_line("Bloquear repetid.",pp.get("block_repeated",""))
                _pp_line("Bloquear username",pp.get("block_username",""))
                _pp_line("Expiración (días)",pp.get("expiration_period",""))
                _pp_line("Aviso expir.",     pp.get("expiration_warning","") + " días")
                _pp_line("Tiempo bloqueo",   pp.get("lockout_time","") + " min")
                _pp_line("Intentos fallidos",pp.get("failed_attempts",""))

            # --- 5. Auth Sequences ---
            _section("5. Authentication sequences  (delegación)")
            if not r["auth_sequences"]:
                print("  |    (ninguna)")
            else:
                for seq in r["auth_sequences"]:
                    print(f"  |    * {seq['seq_name']:<30} perfiles: {seq['profiles']}")
                    total_items += 1

            # --- 6. Usuarios y grupos locales ---
            _section("6. Usuarios y grupos locales  (pertenencia a grupos)")
            local = r["local_users"] + r["local_groups"]
            if not local:
                print("  |    (ninguno)")
            else:
                for lu in r["local_users"]:
                    grupos = r["user_group_membership"].get(lu["name"], [])
                    print(f"  |    [user]  {lu['name']:<30} disabled={lu['disabled']}"
                          f"  grupos: {', '.join(grupos) if grupos else '(sin grupos)'}")
                    total_items += 1
                for lg in r["local_groups"]:
                    print(f"  |    [group] {lg['name']:<30} miembros: {lg['member']}")
                    total_items += 1

            # --- 7. Vsys y accesos ---
            _section("7. Virtual Systems (vsys)  y acceso de administradores")
            if not r["vsys_access"]:
                print("  |    (sin información de vsys)")
            else:
                for va in r["vsys_access"]:
                    print(f"  |    [vsys: {va['vsys']}]")
                    # Mostrar admins en líneas si son muchos
                    admins_str = va["admins"]
                    if len(admins_str) > 60:
                        for a in admins_str.split("; "):
                            print(f"  |      - {a.strip()}")
                    else:
                        print(f"  |      admins: {admins_str}")
                    total_items += 1

            # --- 8. Servidores AAA ---
            _section("8. Servidores AAA  (nombre e IP, vinculados a auth profiles del punto 3)")
            if not r["aaa_servers"]:
                print("  |    (ninguno)")
            else:
                for srv in r["aaa_servers"]:
                    ip_str = srv["server_ip"] if srv["server_ip"] else "(sin IP)"
                    print(f"  |    [{srv['proto'].upper()}]  perfil: {srv['profile']:<25}"
                          f"  nombre: {srv['server_name']:<20}"
                          f"  IP: {ip_str}:{srv['port']}"
                          f"  timeout={srv['timeout']}s")
                    total_items += 1

            # --- 9. Group Mapping ---
            _section("9. Group mapping  (pertenencia a grupos AD/LDAP)")
            if not r["group_mapping"]:
                print("  |    (ninguno — grupos gestionados en servidor externo)")
            else:
                for gm in r["group_mapping"]:
                    print(f"  |    * {gm['mapping_name']:<25}"
                          f"  servidor: {gm['server_profile']}"
                          f"  dominio: {gm['domain']}")
                    print(f"  |      grupos incluidos: {gm['groups_included']}")
                    total_items += 1

            # --- 10. Templates ---
            _section("10. Templates de Panorama  (origen de la configuración)")
            tmpls = dev.get("templates", [])
            stks  = dev.get("stacks", [])
            if not tmpls and not stks:
                print("  |    Sin plantilla asignada — configuración totalmente local")
            else:
                for t in tmpls:
                    print(f"  |    [template]       {t}")
                    total_items += 1
                for s in stks:
                    print(f"  |    [template-stack] {s}")
                    total_items += 1

            # --- 12. Log Forwarding Profiles ---
            _section("12. Log Forwarding Profiles  (Objects > Log Forwarding)")
            if not r["log_forwarding"]:
                print("  |    (ninguno configurado)")
            else:
                for lf in r["log_forwarding"]:
                    print(f"  |    * {lf['profile_name']:<30}  {lf['description']}")
                    for ml in lf["match_list"]:
                        audit = " *** AUDIT/SYSTEM ***" if ml["is_audit"] else ""
                        print(f"  |      [{ml['log_type']}] {ml['name']}"
                              f"  → {ml['destinations']}{audit}")
                    total_items += 1

            # --- 12b. Device Log Settings ---
            dl = r["device_log"]
            _section("12b. Device Log Settings  (destino de System/Config log)")
            pan_str = "SÍ → Panorama" if dl["panorama"] else "NO → Panorama"
            print(f"  |    Envío a Panorama : {pan_str}")
            all_entries = dl["system_entries"] + dl["config_entries"]
            if not all_entries:
                print("  |    (sin reglas de log forwarding configuradas)")
            else:
                for e in all_entries:
                    syslog_str = f"syslog: {e['syslog']}" if e["syslog"] else "(sin syslog externo)"
                    pan_e      = "panorama: SÍ" if e["panorama"] else "panorama: NO"
                    print(f"  |    [{e['log_type']}] {e['name']:<25}  {pan_e}  {syslog_str}")
                total_items += 1

            # --- 13. Syslog Servers ---
            _section("13. Servidores Syslog configurados")
            if not r["syslog_servers"]:
                print("  |    (ninguno)")
            else:
                for sl in r["syslog_servers"]:
                    print(f"  |    * {sl['syslog_profile']}/{sl['server_name']:<20}"
                          f"  {sl['server_addr']}:{sl['port']}"
                          f"  {sl['transport']}  fmt={sl['format']}"
                          f"  facility={sl['facility']}")
                    total_items += 1

            # --- 15. Permitted IPs ---
            _section("15. Fuentes de gestión permitidas  (Permitted IP)")
            pips = r["permitted_ips"]
            if not pips:
                print("  |    (sin restricción — cualquier origen permitido)")
            else:
                for pip in pips:
                    print(f"  |    * {pip}")
                    total_items += 1

            print(f"  +" + _hr())

        print(f"  ╚{'═' * 68}")

    print()
    print("=" * 70)
    print(f"  Total dispositivos  : {total_devs}")
    print(f"  Total items         : {total_items}")
    print("=" * 70)


# ---------------------------------------------------------------------------
# Vista 2 — Por Usuario
# ---------------------------------------------------------------------------

def print_by_user(all_results: list[dict]) -> None:
    user_map: dict[str, list[dict]] = {}

    for r in all_results:
        dev       = r["device"]
        dev_label = f"{dev['name'] or dev['serial']} ({', '.join(dev['dg_list']) or 'sin DG'})"

        for adm in r["admins"]:
            uname = adm["username"]
            rl    = ROLE_LABELS.get(adm["role_type"], adm["role_type"])
            if adm["role_name"]:
                rl += f" -> {adm['role_name']}"
            auth_full = adm["auth_type"]
            if adm["auth_server"]:
                auth_full += f" -> {adm['auth_server']}"
            user_map.setdefault(uname, []).append({
                "device":          dev_label,
                "role":            rl,
                "status":          adm["account_status"],
                "auth":            auth_full,
                "failed_attempts": adm["failed_attempts"],
            })

        for lu in r["local_users"]:
            grupos = r["user_group_membership"].get(lu["name"], [])
            user_map.setdefault(lu["name"], []).append({
                "device":          dev_label,
                "role":            "usuario local vsys",
                "status":          "DESHABILITADO" if lu["disabled"] in ("yes","true","1") else "ACTIVO",
                "auth":            "LOCAL",
                "failed_attempts": "",
                "groups":          ", ".join(grupos) if grupos else "(sin grupos)",
            })

    print()
    print("=" * 70)
    print("  AUDITORÍA — Vista por Usuario")
    print("=" * 70)
    print(f"  Usuarios únicos identificados: {len(user_map)}")

    for uname in sorted(user_map.keys()):
        appearances = user_map[uname]
        print()
        print(f"  ┌─ Usuario: {uname} ({len(appearances)} aparición(es))")
        for ap in appearances:
            lock_info = (
                f"  intentos={ap['failed_attempts']}"
                if ap.get("failed_attempts") and ap["failed_attempts"] not in ("0","") else ""
            )
            grupos_str = f"  grupos: {ap['groups']}" if ap.get("groups") else ""
            print(f"  │  Firewall : {ap['device']}")
            print(f"  │  Rol      : {ap['role']}")
            print(f"  │  Estado   : [{ap['status']}]{lock_info}")
            print(f"  │  Auth     : {ap['auth']}{grupos_str}")
            print(f"  │")
        print(f"  └{'─' * 68}")

    print()
    print("=" * 70)
    print(f"  Total usuarios únicos: {len(user_map)}")
    print("=" * 70)


# ---------------------------------------------------------------------------
# Exportación CSV
# ---------------------------------------------------------------------------

CSV_FIELDS = [
    "device_name", "serial", "model", "sw_version", "ip", "device_groups",
    "section", "item_name", "field1", "field2", "field3", "field4", "field5",
]


def _row(dev: dict, section: str, item_name: str,
         f1="", f2="", f3="", f4="", f5="") -> dict:
    return {
        "device_name":   dev["name"] or "",
        "serial":        dev["serial"],
        "model":         dev["model"],
        "sw_version":    dev["sw_version"],
        "ip":            dev["ip"],
        "device_groups": "; ".join(dev["dg_list"]),
        "section":       section,
        "item_name":     item_name,
        "field1": f1, "field2": f2, "field3": f3, "field4": f4, "field5": f5,
    }


def export_to_csv(results_by_dg: dict[str, list[dict]], filepath: str) -> None:
    rows = []
    for dg_name, results in results_by_dg.items():
        for r in results:
            dev = r["device"]
            pp  = r["password_policy"]
            pp_enabled = pp.get("enabled", "") == "yes"
            pw_summary = (
                f"mín.{pp.get('minimum_length','?')} chars, expira {pp.get('expiration_period','?')}d"
                if pp_enabled else "sin política"
            )

            # 01 Admins
            for adm in r["admins"] or [{}]:
                rl = ROLE_LABELS.get(adm.get("role_type",""), adm.get("role_type",""))
                if adm.get("role_name"):
                    rl += f" -> {adm['role_name']}"
                auth = adm.get("auth_type","")
                if adm.get("auth_server"):
                    auth += f" -> {adm['auth_server']}"
                rows.append(_row(dev, "01_admins", adm.get("username",""),
                                 f"estado={adm.get('account_status','')}",
                                 rl, auth, pw_summary,
                                 f"locked={adm.get('locked','')}"))

            # 02 Custom roles
            for ro in r["custom_roles"] or [{}]:
                rows.append(_row(dev, "02_custom_roles", ro.get("role_name",""),
                                 f"interfaces={ro.get('interfaces','')}",
                                 f"scope={ro.get('vsys_scope','')}",
                                 f"usado_por={ro.get('used_by','')}"))

            # 03 Auth profiles
            for ap in r["auth_profiles"] or [{}]:
                rows.append(_row(dev, "03_auth_profiles", ap.get("profile_name",""),
                                 f"origen={ap.get('auth_origin','')}",
                                 f"servidor={ap.get('server_ip','')}",
                                 f"usuarios={', '.join(ap.get('users',[]))}",
                                 f"mfa={ap.get('mfa_factors','')}"))

            # 04 Password policy
            for k, v in (pp or {}).items():
                rows.append(_row(dev, "04_password_policy", k, str(v)))

            # 05 Auth sequences
            for seq in r["auth_sequences"] or [{}]:
                rows.append(_row(dev, "05_auth_sequences", seq.get("seq_name",""),
                                 f"profiles={seq.get('profiles','')}"))

            # 06 Local users
            for lu in r["local_users"] or [{}]:
                grupos = r["user_group_membership"].get(lu.get("name",""), [])
                rows.append(_row(dev, "06_local_users", lu.get("name",""),
                                 f"disabled={lu.get('disabled','')}",
                                 f"grupos={', '.join(grupos)}"))

            # 06b Groups
            for lg in r["local_groups"] or [{}]:
                rows.append(_row(dev, "06_local_groups", lg.get("name",""),
                                 f"miembros={lg.get('member','')}"))

            # 07 vsys access
            for va in r["vsys_access"] or [{}]:
                rows.append(_row(dev, "07_vsys_access", va.get("vsys",""),
                                 va.get("admins","")))

            # 08 AAA servers
            for srv in r["aaa_servers"] or [{}]:
                rows.append(_row(dev, "08_aaa_servers", srv.get("profile",""),
                                 f"proto={srv.get('proto','')}",
                                 f"nombre={srv.get('server_name','')}",
                                 f"ip={srv.get('server_ip','')}:{srv.get('port','')}",
                                 f"timeout={srv.get('timeout','')}s"))

            # 09 Group mapping
            for gm in r["group_mapping"] or [{}]:
                rows.append(_row(dev, "09_group_mapping", gm.get("mapping_name",""),
                                 f"server={gm.get('server_profile','')}",
                                 f"domain={gm.get('domain','')}",
                                 f"grupos_inc={gm.get('groups_included','')}"))

            # 10 Templates
            for t in dev.get("templates", []) or [""]:
                rows.append(_row(dev, "10_templates", t, "plantilla=SÍ"))
            for s in dev.get("stacks", []) or [""]:
                rows.append(_row(dev, "10_template_stacks", s, "plantilla=SÍ"))

            # 12 Log Forwarding Profiles
            for lf in r["log_forwarding"] or [{}]:
                for ml in lf.get("match_list", [{}]):
                    rows.append(_row(dev, "12_log_forwarding", lf.get("profile_name",""),
                                     f"log_type={ml.get('log_type','')}",
                                     f"match={ml.get('name','')}",
                                     f"destinos={ml.get('destinations','')}",
                                     f"is_audit={ml.get('is_audit','')}"))

            # 12b Device Log Settings
            dl = r.get("device_log", {})
            rows.append(_row(dev, "12b_device_log", "system+config",
                             f"panorama={dl.get('panorama','')}",
                             f"syslog_profiles={'; '.join(dl.get('syslog_profiles',[]))}"))

            # 13 Syslog
            for sl in r["syslog_servers"] or [{}]:
                rows.append(_row(dev, "13_syslog_servers",
                                 f"{sl.get('syslog_profile','')}/{sl.get('server_name','')}",
                                 f"{sl.get('server_addr','')}:{sl.get('port','')}",
                                 f"transport={sl.get('transport','')}",
                                 f"format={sl.get('format','')}",
                                 f"facility={sl.get('facility','')}"))

            # 15 Permitted IPs
            for pip in r["permitted_ips"] or [""]:
                rows.append(_row(dev, "15_permitted_ips", pip))

    with open(filepath, mode="w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[OK] Exportado a CSV: {filepath}  ({len(rows)} filas)")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Auditoría de accesos y configuración de seguridad en firewalls "
            "Palo Alto Networks gestionados por Panorama (proxy de API)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--sn",           metavar="SERIAL")
    group.add_argument("--device-name",  metavar="NOMBRE")
    group.add_argument("--device-group", metavar="DG")

    parser.add_argument("--group-by", metavar="MODE",
                        choices=["firewall", "user", "both"],
                        help="firewall | user | both  (omite la pregunta interactiva)")
    parser.add_argument("--no-export", action="store_true",
                        help="No generar los ficheros CSV/JSON de exportación.")
    parser.add_argument("--output-dir", metavar="DIR", default=".",
                        help="Directorio donde guardar los ficheros de exportación (default: .)")
    parser.add_argument("--debug",  action="store_true")
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Exportación 1 — Users audit CSV
# ---------------------------------------------------------------------------

USERS_CSV_FIELDS = [
    "device_name", "serial", "model", "sw_version", "ip", "device_groups",
    "username", "user_state", "user_rol", "user_type",
    "password_complexity", "password_policy", "locked",
]


def _user_rol_str(adm: dict) -> str:
    """Genera la cadena de rol según el formato solicitado."""
    role_type = adm.get("role_type", "")
    role_name = adm.get("role_name", "")
    base = ROLE_LABELS.get(role_type, role_type)
    if role_type == "custom" and role_name:
        return f"Custom Role | {role_name}"
    return base


def _user_type_str(adm: dict) -> str:
    """LOCAL o REMOTE (PROTO) -> profile_name."""
    auth_type = adm.get("auth_type", "LOCAL")
    profile   = adm.get("auth_profile_name", "")
    if auth_type.startswith("REMOTO"):
        # Convertir "REMOTO (RADIUS)" → "REMOTE (RADIUS)"
        auth_type_en = auth_type.replace("REMOTO", "REMOTE")
        if profile:
            return f"{auth_type_en} -> {profile}"
        return auth_type_en
    return "LOCAL"


def export_users_csv(all_results: list[dict], filepath: str) -> None:
    """
    Genera el CSV de usuarios con una fila por cada admin en cada dispositivo.
    Formato: device_name, serial, ..., username, user_state, user_rol,
             user_type, password_complexity, password_policy, locked
    """
    rows = []
    for r in all_results:
        dev        = r["device"]
        pp         = r["password_policy"]
        pp_enabled = "enabled" if pp.get("enabled") == "yes" else "disabled"

        for adm in r["admins"]:
            # password_policy: nombre del perfil si tiene uno explícito, si no vacío
            pw_policy = adm.get("pw_profile", "")

            rows.append({
                "device_name":        dev["name"] or "",
                "serial":             dev["serial"],
                "model":              dev["model"],
                "sw_version":         dev["sw_version"],
                "ip":                 dev["ip"],
                "device_groups":      "; ".join(dev["dg_list"]),
                "username":           adm["username"],
                "user_state":         adm["account_status"],
                "user_rol":           _user_rol_str(adm),
                "user_type":          _user_type_str(adm),
                "password_complexity": pp_enabled,
                "password_policy":    pw_policy,
                "locked":             adm.get("locked", "NO"),
            })

    with open(filepath, mode="w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=USERS_CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[OK] Users audit CSV: {filepath}  ({len(rows)} filas)")


# ---------------------------------------------------------------------------
# Exportación 2 — Device audit JSON
# ---------------------------------------------------------------------------

def _build_device_json(r: dict) -> dict:
    """
    Construye el dict JSON de un dispositivo con todas las secciones.
    Los campos son variables por sección, de ahí el formato JSON.
    """
    dev = r["device"]
    pp  = r["password_policy"]

    return {
        "device": {
            "name":         dev["name"] or "",
            "serial":       dev["serial"],
            "model":        dev["model"],
            "sw_version":   dev["sw_version"],
            "ip":           dev["ip"],
            "device_groups": dev["dg_list"],
            "templates":    dev.get("templates", []),
            "stacks":       dev.get("stacks", []),
        },
        "admins": [
            {
                "username":           a["username"],
                "state":              a["account_status"],
                "role_type":          a["role_type"],
                "role_label":         _user_rol_str(a),
                "role_custom":        a.get("role_name", ""),
                "auth_type":          _user_type_str(a),
                "auth_profile":       a.get("auth_profile_name", ""),
                "auth_server":        a.get("auth_server", ""),
                "password_profile":   a.get("pw_profile", ""),
                "locked":             a.get("locked", "NO"),
                "failed_attempts":    a.get("failed_attempts", "0"),
            }
            for a in r["admins"]
        ],
        "custom_roles": [
            {
                "name":      ro["role_name"],
                "scope":     ro["vsys_scope"],
                "used_by":   ro["used_by"],
            }
            for ro in r["custom_roles"]
        ],
        "auth_profiles": [
            {
                "name":           ap["profile_name"],
                "auth_origin":    ap["auth_origin"],
                "method":         ap["method"],
                "server_profile": ap.get("server_profile", ""),
                "server_ip":      ap.get("server_ip", ""),
                "mfa_factors":    ap.get("mfa_factors", ""),
                "allow_list":     ap.get("allow_list", ""),
                "users":          ap.get("users", []),
            }
            for ap in r["auth_profiles"]
        ],
        "password_policy": pp,
        "auth_sequences": [
            {
                "name":       seq["seq_name"],
                "profiles":   seq["profiles"],
                "use_domain": seq["use_domain"],
            }
            for seq in r["auth_sequences"]
        ],
        "local_users": [
            {
                "name":     u["name"],
                "disabled": u["disabled"],
                "groups":   r["user_group_membership"].get(u["name"], []),
            }
            for u in r["local_users"]
        ],
        "local_groups": [
            {
                "name":    g["name"],
                "members": g["member"].split("; ") if g["member"] else [],
            }
            for g in r["local_groups"]
        ],
        "vsys_access": r["vsys_access"],
        "aaa_servers": [
            {
                "protocol":     srv["proto"],
                "profile":      srv["profile"],
                "server_name":  srv["server_name"],
                "server_ip":    srv["server_ip"],
                "port":         srv["port"],
                "timeout":      srv["timeout"],
            }
            for srv in r["aaa_servers"]
        ],
        "group_mapping": [
            {
                "name":            gm["mapping_name"],
                "server_profile":  gm["server_profile"],
                "domain":          gm["domain"],
                "groups_included": gm["groups_included"],
                "groups_excluded": gm["groups_excluded"],
            }
            for gm in r["group_mapping"]
        ],
        "log_forwarding_profiles": [
            {
                "name":        lf["profile_name"],
                "description": lf["description"],
                "match_list": [
                    {
                        "name":         ml["name"],
                        "log_type":     ml["log_type"],
                        "destinations": ml["destinations"],
                        "is_audit":     ml["is_audit"],
                    }
                    for ml in lf["match_list"]
                ],
            }
            for lf in r["log_forwarding"]
        ],
        "device_log_settings": {
            "send_to_panorama": r["device_log"].get("panorama", False),
            "system_log": [
                {
                    "rule":     e["name"],
                    "panorama": e["panorama"],
                    "syslog":   e["syslog"],
                }
                for e in r["device_log"].get("system_entries", [])
            ],
            "config_log": [
                {
                    "rule":     e["name"],
                    "panorama": e["panorama"],
                    "syslog":   e["syslog"],
                }
                for e in r["device_log"].get("config_entries", [])
            ],
        },
        "syslog_servers": [
            {
                "profile":    sl["syslog_profile"],
                "name":       sl["server_name"],
                "address":    sl["server_addr"],
                "port":       sl["port"],
                "transport":  sl["transport"],
                "format":     sl["format"],
                "facility":   sl["facility"],
            }
            for sl in r["syslog_servers"]
        ],
        "permitted_ips": r["permitted_ips"],
    }


def export_device_json(all_results: list[dict], filepath: str) -> None:
    """
    Genera el JSON de auditoría de dispositivos.
    Estructura: lista de dispositivos, cada uno con todas sus secciones.
    """
    import json

    payload = {
        "generated_at": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "panorama":     PAN_URL,
        "devices":      [_build_device_json(r) for r in all_results],
    }

    with open(filepath, mode="w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)

    print(f"[OK] Device audit JSON: {filepath}  ({len(all_results)} dispositivos)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()

    print("=" * 70)
    print("  Panorama Security Audit — Accesos y Configuración")
    print("=" * 70)
    print(f"  Panorama  : {PAN_URL}")
    print(f"  Timestamp : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if args.sn:
        print(f"  Filtro    : Serial = {args.sn}")
    elif args.device_name:
        print(f"  Filtro    : Nombre = {args.device_name}")
    elif args.device_group:
        print(f"  Filtro    : Device Group = {args.device_group}")
    else:
        print("  Filtro    : Todos los dispositivos conectados")
    print("=" * 70)

    # Siempre vista por Device Group / Firewall
    group_by = args.group_by if args.group_by else "firewall"

    print()
    devices = get_connected_devices()
    devices = filter_devices(devices, args)
    print(f"\n[INFO] Auditando {len(devices)} dispositivo(s)...\n")

    all_results: list[dict] = []
    for dev in devices:
        all_results.append(collect_device_data(dev))

    results_by_dg: dict[str, list[dict]] = {}
    for r in all_results:
        key = (r["device"]["dg_list"] or ["(Sin Device Group)"])[0]
        results_by_dg.setdefault(key, []).append(r)

    if group_by in ("firewall", "both"):
        print_by_firewall(results_by_dg)

    if group_by in ("user", "both"):
        print_by_user(all_results)

    # --- Exportación automática de los dos ficheros con fecha ---
    if not args.no_export:
        import os
        date_prefix = datetime.now().strftime("%Y%m%d")
        out_dir     = args.output_dir
        os.makedirs(out_dir, exist_ok=True)

        csv_path  = os.path.join(out_dir, f"{date_prefix}_01-users_audit.csv")
        json_path = os.path.join(out_dir, f"{date_prefix}_02-device_audit.json")

        print()
        export_users_csv(all_results, csv_path)
        export_device_json(all_results, json_path)

    if args.debug:
        with open("debug.txt", "w", encoding="utf-8") as fh:
            fh.write("\n".join(DEBUG_LINES))
        print(f"[OK] Debug guardado en debug.txt ({len(DEBUG_LINES)} líneas)")


if __name__ == "__main__":
    main()


# ----------------------------