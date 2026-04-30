#!/usr/bin/env python3
"""
pan_device_admins.py
--------------------
Obtiene los usuarios administradores y sus roles configurados en los firewalls
conectados a Panorama, utilizando Panorama como proxy (parámetro target=<serial>).

Flujo:
  1. Consulta a Panorama la lista de dispositivos conectados.
  2. Filtra los dispositivos según los argumentos proporcionados.
  3. Para cada dispositivo, consulta via Panorama (target=serial) los administradores
     configurados localmente en el firewall.
  4. Muestra un resumen organizado por dispositivo.

Uso:
  python pan_device_admins.py                                     # Todos los equipos conectados
  python pan_device_admins.py --sn 0123456789ABCDEF              # Un equipo por serial number
  python pan_device_admins.py --device-name FW-PRODUCCION        # Un equipo por nombre
  python pan_device_admins.py --device-group DG-CORP             # Equipos de un device group
  python pan_device_admins.py --output admins.csv                # Exportar resultado a CSV

Requisitos (.env):
  PAN_URL=https://<panorama-ip-o-fqdn>
  PAN_API_KEY=<api-key>
"""

import argparse
import csv
import sys
import os
import urllib3
import xml.etree.ElementTree as ET
from collections import defaultdict

import requests
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Configuración inicial
# ---------------------------------------------------------------------------

# Suprimir advertencias de certificado SSL auto-firmado (habitual en Panorama)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

PAN_URL = os.getenv("PAN_URL", "").rstrip("/")
PAN_API_KEY = os.getenv("PAN_API_KEY", "")

if not PAN_URL or not PAN_API_KEY:
    sys.exit("[ERROR] PAN_URL y PAN_API_KEY deben estar definidas en el fichero .env")

# Timeout por defecto para llamadas a dispositivos remotos (puede ser más lento)
TIMEOUT_PANORAMA = 30
TIMEOUT_DEVICE = 45


# ---------------------------------------------------------------------------
# Helpers de API
# ---------------------------------------------------------------------------

def _api_get(params: dict, timeout: int = TIMEOUT_PANORAMA) -> ET.Element:
    """
    Realiza una llamada GET a la API XML de Panorama y devuelve el XML parseado.
    Lanza SystemExit si la respuesta no es 'success'.
    """
    params["key"] = PAN_API_KEY
    try:
        resp = requests.get(
            f"{PAN_URL}/api/",
            params=params,
            verify=False,
            timeout=timeout,
        )
        resp.raise_for_status()
    except requests.exceptions.Timeout:
        raise RuntimeError("Timeout al conectar con Panorama")
    except requests.RequestException as exc:
        raise RuntimeError(f"Error de conexión con Panorama: {exc}")

    root = ET.fromstring(resp.text)
    status = root.attrib.get("status", "")
    if status != "success":
        msg = root.findtext(".//msg") or resp.text[:200]
        raise RuntimeError(f"La API devolvió status='{status}': {msg}")

    return root


# ---------------------------------------------------------------------------
# Obtención de dispositivos conectados a Panorama
# ---------------------------------------------------------------------------

def get_device_group_map() -> dict[str, list[str]]:
    """
    Consulta la configuración de Panorama para obtener la asignación
    de seriales a device groups.

    XPath: /config/devices/entry[@name='localhost.localdomain']/device-group/entry
    Cada <entry name="DG"> contiene <devices><entry name="SERIAL"/>...</devices>

    Devuelve un dict { serial -> [dg1, dg2, ...] }
    """
    xpath = (
        "/config/devices/entry[@name='localhost.localdomain']"
        "/device-group/entry"
    )
    serial_to_dgs: dict[str, list[str]] = {}
    try:
        root = _api_get({"type": "config", "action": "get", "xpath": xpath})
        for dg_entry in root.findall(".//entry"):
            dg_name = dg_entry.get("name", "")
            if not dg_name:
                continue
            for dev_entry in dg_entry.findall(".//devices/entry"):
                serial = dev_entry.get("name", "")
                if serial:
                    serial_to_dgs.setdefault(serial, []).append(dg_name)
    except RuntimeError as exc:
        print(f"  [WARN] No se pudo obtener el mapa de device groups: {exc}")

    return serial_to_dgs


def get_connected_devices() -> list[dict]:
    """
    Ejecuta el comando operacional 'show devices connected' en Panorama
    y devuelve una lista de dicts con los campos relevantes de cada dispositivo:
      - serial    : Serial number
      - name      : Hostname del firewall
      - ip        : IP de gestion
      - model     : Modelo (PA-xxx, VM-xxx...)
      - sw_version: Version de PAN-OS
      - connected : Estado de conexion
      - dg_list   : Lista de device groups a los que pertenece
    """
    print("[INFO] Consultando dispositivos conectados a Panorama...")
    root = _api_get({
        "type": "op",
        "cmd": "<show><devices><connected/></devices></show>",
    })

    # Mapa serial -> [DGs] obtenido de la config de Panorama
    dg_map = get_device_group_map()

    devices = []
    for entry in root.findall(".//devices/entry"):
        serial    = entry.findtext("serial") or entry.get("name", "")
        name      = entry.findtext("hostname") or entry.findtext("devicename") or ""
        ip        = entry.findtext("ip-address") or ""
        model     = entry.findtext("model") or ""
        sw_ver    = entry.findtext("sw-version") or ""
        connected = entry.findtext("connected") or "no"

        # Usar el mapa de config; fallback al campo del response operacional
        dg_list = dg_map.get(serial) or [
            dg.get("name", "")
            for dg in entry.findall(".//device-group/entry")
            if dg.get("name")
        ]

        devices.append({
            "serial":     serial,
            "name":       name,
            "ip":         ip,
            "model":      model,
            "sw_version": sw_ver,
            "connected":  connected,
            "dg_list":    dg_list,
        })

    print(f"[INFO] {len(devices)} dispositivo(s) conectado(s) encontrado(s).")
    return devices


# ---------------------------------------------------------------------------
# Filtrado de dispositivos según argumentos CLI
# ---------------------------------------------------------------------------

def filter_devices(devices: list[dict], args: argparse.Namespace) -> list[dict]:
    """Filtra la lista de dispositivos según los argumentos recibidos."""
    if args.sn:
        filtered = [d for d in devices if d["serial"].upper() == args.sn.upper()]
        if not filtered:
            sys.exit(f"[ERROR] No se encontró ningún dispositivo conectado con serial '{args.sn}'")
        return filtered

    if args.device_name:
        filtered = [
            d for d in devices
            if d["name"].lower() == args.device_name.lower()
        ]
        if not filtered:
            sys.exit(
                f"[ERROR] No se encontró ningún dispositivo conectado con nombre '{args.device_name}'"
            )
        return filtered

    if args.device_group:
        filtered = [
            d for d in devices
            if any(dg.lower() == args.device_group.lower() for dg in d["dg_list"])
        ]
        if not filtered:
            sys.exit(
                f"[ERROR] No se encontró ningún dispositivo en el device group '{args.device_group}'"
            )
        return filtered

    # Sin filtros → todos
    return devices


# ---------------------------------------------------------------------------
# Consulta de administradores en cada dispositivo (via Panorama como proxy)
# ---------------------------------------------------------------------------

def get_device_admins(serial: str, device_name: str) -> list[dict]:
    """
    Consulta los administradores configurados en un firewall concreto,
    utilizando Panorama como proxy mediante el parámetro target=<serial>.

    El XPath apunta a la sección de usuarios administradores locales:
      /config/mgt-config/users/entry

    Cada entry tiene:
      - @name        : nombre de usuario
      - permissions  : tipo de rol (superuser, superreader, deviceadmin, devicereader...)
      - role-based   : si usa un rol personalizado, aquí está el nombre del perfil
      - phash        : hash de contraseña (no se muestra)

    Devuelve una lista de dicts { username, role_type, role_name }.
    """
    xpath = "/config/mgt-config/users/entry"
    try:
        root = _api_get(
            {
                "type":   "config",
                "action": "get",
                "xpath":  xpath,
                "target": serial,
            },
            timeout=TIMEOUT_DEVICE,
        )
    except RuntimeError as exc:
        print(f"  [WARN] No se pudo consultar '{device_name}' ({serial}): {exc}")
        return []

    admins = []
    for entry in root.findall(".//entry"):
        username = entry.get("name", "")
        role_type = ""
        role_name = ""

        permissions = entry.find("permissions")
        if permissions is not None:
            # Rol predefinido: superuser, superreader, deviceadmin, devicereader
            role_elem = permissions.find("role-based")
            if role_elem is not None:
                # Si tiene subelemento → es un perfil personalizado
                custom = role_elem.find("custom")
                if custom is not None:
                    role_type = "custom"
                    role_name = custom.findtext("profile") or ""
                else:
                    # Es un rol predefinido: el texto del primer hijo
                    for child in role_elem:
                        role_type = child.tag
                        break
            else:
                # Compatibilidad con versiones antiguas: <superuser/> directamente en <permissions>
                for child in permissions:
                    role_type = child.tag
                    break

        # Fallback: buscar <superuser/> o <superreader/> directamente bajo <entry>
        if not role_type:
            for tag in ("superuser", "superreader", "deviceadmin", "devicereader"):
                if entry.find(tag) is not None:
                    role_type = tag
                    break

        admins.append({
            "username":  username,
            "role_type": role_type or "unknown",
            "role_name": role_name,
        })

    return admins


# ---------------------------------------------------------------------------
# Presentación de resultados
# ---------------------------------------------------------------------------

ROLE_LABELS = {
    "superuser":    "Super User (acceso total)",
    "superreader":  "Super Reader (solo lectura)",
    "deviceadmin":  "Device Administrator",
    "devicereader": "Device Reader (solo lectura)",
    "custom":       "Rol personalizado",
    "unknown":      "Rol desconocido",
}


def print_results(results: list[dict]) -> None:
    """Imprime los resultados de forma legible."""
    total_devices = len(results)
    total_admins  = sum(len(r["admins"]) for r in results)

    print()
    print("=" * 70)
    print("  RESULTADO: Administradores por dispositivo")
    print("=" * 70)

    for r in results:
        dev   = r["device"]
        admins = r["admins"]
        dg_str = ", ".join(dev["dg_list"]) if dev["dg_list"] else "-"

        print()
        print(f"  +- Dispositivo : {dev['name'] or '(sin nombre)'}")
        print(f"  |  Serial      : {dev['serial']}")
        print(f"  |  Modelo      : {dev['model']}   PAN-OS: {dev['sw_version']}")
        print(f"  |  IP gestion  : {dev['ip']}")
        print(f"  |  Device Group: {dg_str}")
        print(f"  |  Admins ({len(admins)}):")

        if not admins:
            print("  |    (sin administradores locales o sin acceso)")
        else:
            for adm in admins:
                role_label = ROLE_LABELS.get(adm["role_type"], adm["role_type"])
                if adm["role_name"]:
                    role_label += f" -> perfil: '{adm['role_name']}'"
                print(f"  |    * {adm['username']:<25} {role_label}")

        print("  +" + "-" * 67)

    print()
    print("=" * 70)
    print(f"  Total dispositivos consultados : {total_devices}")
    print(f"  Total administradores encontrados: {total_admins}")
    print("=" * 70)


# ---------------------------------------------------------------------------
# Exportación CSV
# ---------------------------------------------------------------------------

CSV_FIELDS = [
    "device_name",
    "serial",
    "model",
    "sw_version",
    "ip",
    "device_groups",
    "username",
    "role_type",
    "role_label",
    "role_profile",
]


def export_to_csv(results: list[dict], filepath: str) -> None:
    """
    Exporta los resultados consolidados a un fichero CSV.
    Una fila por cada combinación dispositivo-administrador.
    Si un dispositivo no tiene administradores, se genera igualmente
    una fila con los campos de usuario en blanco.
    """
    with open(filepath, mode="w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()

        for r in results:
            dev = r["device"]
            base = {
                "device_name":   dev["name"] or "",
                "serial":        dev["serial"],
                "model":         dev["model"],
                "sw_version":    dev["sw_version"],
                "ip":            dev["ip"],
                "device_groups": "; ".join(dev["dg_list"]),
            }

            if not r["admins"]:
                writer.writerow({**base, "username": "", "role_type": "",
                                 "role_label": "", "role_profile": ""})
            else:
                for adm in r["admins"]:
                    role_label = ROLE_LABELS.get(adm["role_type"], adm["role_type"])
                    writer.writerow({
                        **base,
                        "username":     adm["username"],
                        "role_type":    adm["role_type"],
                        "role_label":   role_label,
                        "role_profile": adm["role_name"],
                    })

    print(f"[OK] Exportado a CSV: {filepath}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Obtiene los administradores y roles configurados en los firewalls "
            "conectados a Panorama, usando Panorama como proxy de API."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--sn",
        metavar="SERIAL",
        help="Consultar solo el dispositivo con este serial number.",
    )
    group.add_argument(
        "--device-name",
        metavar="NOMBRE",
        help="Consultar solo el dispositivo con este hostname.",
    )
    group.add_argument(
        "--device-group",
        metavar="DEVICE_GROUP",
        help="Consultar solo los dispositivos que pertenezcan a este device group.",
    )

    parser.add_argument(
        "--output",
        metavar="FICHERO.CSV",
        help="Ruta del fichero CSV donde exportar los resultados consolidados.",
    )

    return parser.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()

    print("=" * 70)
    print("  Panorama Device Admins Checker")
    print("=" * 70)
    print(f"  Panorama : {PAN_URL}")

    if args.sn:
        print(f"  Filtro   : Serial = {args.sn}")
    elif args.device_name:
        print(f"  Filtro   : Nombre = {args.device_name}")
    elif args.device_group:
        print(f"  Filtro   : Device Group = {args.device_group}")
    else:
        print("  Filtro   : Todos los dispositivos conectados")

    print("=" * 70)
    print()

    # 1. Obtener dispositivos conectados
    devices = get_connected_devices()

    # 2. Filtrar según argumentos
    devices = filter_devices(devices, args)

    print(f"[INFO] Consultando administradores en {len(devices)} dispositivo(s)...\n")

    # 3. Consultar admins en cada dispositivo
    results = []
    for dev in devices:
        label = dev["name"] or dev["serial"]
        print(f"[INFO] -> {label} ({dev['serial']}) ...")
        admins = get_device_admins(dev["serial"], label)
        results.append({"device": dev, "admins": admins})

    # 4. Mostrar resultados
    print_results(results)

    # 5. Exportar a CSV si se indicó
    if args.output:
        export_to_csv(results, args.output)


if __name__ == "__main__":
    main()
