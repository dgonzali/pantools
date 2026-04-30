#!/usr/bin/env python3
"""
rule_renamer.py
---------------
Renombra una regla de política de seguridad en Panorama usando su UUID.

Flujo:
  1. Busca la regla por UUID (XPath con predicado @uuid) para obtener su nombre actual.
  2. Usa el comando 'rename' de la API con el nombre actual para aplicar el nuevo nombre.

Uso:
  python rule_renamer.py --uuid <UUID> --device-group <DG> --new-name <NUEVO_NOMBRE>

Ejemplos:
  python rule_renamer.py \
      --uuid "12345678-abcd-1234-abcd-1234567890ab" \
      --device-group "DG-PRODUCCION" \
      --new-name "Allow-HTTP-Nuevo"
"""

import argparse
import sys
import urllib3
import xml.etree.ElementTree as ET

import requests
from dotenv import load_dotenv
import os

# Suprimir advertencias de certificado SSL auto-firmado (habitual en Panorama)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Cargar variables de entorno
# ---------------------------------------------------------------------------
load_dotenv()

PAN_URL = os.getenv("PAN_URL", "").rstrip("/")
PAN_API_KEY = os.getenv("PAN_API_KEY", "")

if not PAN_URL or not PAN_API_KEY:
    sys.exit("[ERROR] PAN_URL y PAN_API_KEY deben estar definidas en el fichero .env")


# ---------------------------------------------------------------------------
# Helpers de API
# ---------------------------------------------------------------------------

def _api_get(params: dict) -> ET.Element:
    """Realiza una llamada GET a la API XML de Panorama y devuelve el XML parseado."""
    params["key"] = PAN_API_KEY
    try:
        resp = requests.get(
            f"{PAN_URL}/api/",
            params=params,
            verify=False,
            timeout=30,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        sys.exit(f"[ERROR] Error de conexión con Panorama: {exc}")

    root = ET.fromstring(resp.text)
    status = root.attrib.get("status", "")
    if status != "success":
        msg = root.findtext(".//msg") or resp.text
        sys.exit(f"[ERROR] La API devolvió status='{status}': {msg}")

    return root


# Nombre especial de Panorama para las reglas compartidas
_SHARED = "Shared"


def _build_base_xpath(device_group: str) -> str:
    """
    Devuelve el XPath base según el contexto:

    - Device Group normal:
        /config/devices/entry[@name='localhost.localdomain']
          /device-group/entry[@name='<DG>']

    - Shared (nivel global de Panorama):
        /config/shared

    Las reglas Shared NO están bajo /device-group/entry[@name='Shared'],
    sino directamente bajo /config/shared/pre-rulebase/...
    """
    if device_group.strip().lower() == _SHARED.lower():
        return "/config/shared"
    return (
        "/config/devices/entry[@name='localhost.localdomain']"
        f"/device-group/entry[@name='{device_group}']"
    )


def get_rule_name_by_uuid(uuid: str, device_group: str) -> str:
    """
    Recupera el nombre actual de la regla buscando por UUID.

    Rutas XPath según contexto:
      - DG normal : /config/devices/.../device-group/entry[@name='<DG>']/<rulebase>/...
      - Shared    : /config/shared/<rulebase>/...

    Prueba pre-rulebase y post-rulebase en ese orden.
    """
    base_xpath = _build_base_xpath(device_group)

    for rulebase in ("pre-rulebase", "post-rulebase"):
        xpath = f"{base_xpath}/{rulebase}/security/rules/entry[@uuid='{uuid}']"
        print(f"[INFO] Buscando regla en {rulebase} con XPath:\n       {xpath}")

        root = _api_get({"type": "config", "action": "get", "xpath": xpath})

        # Si la respuesta tiene un <entry> con nombre, lo encontramos
        entry = root.find(".//entry")
        if entry is not None:
            rule_name = entry.attrib.get("name")
            if rule_name:
                print(f"[INFO] Regla encontrada en {rulebase}: '{rule_name}'")
                return rule_name, rulebase

    sys.exit(
        f"[ERROR] No se encontró ninguna regla con UUID '{uuid}' "
        f"en el contexto '{device_group}'."
    )


def rename_rule(device_group: str, rulebase: str, current_name: str, new_name: str) -> None:
    """
    Renombra la regla usando el comando 'rename' de la API de Panorama.

    El comando rename requiere el nombre actual (no el UUID), por eso
    primero se resuelve el nombre con get_rule_name_by_uuid().
    Usa _build_base_xpath para construir la ruta correcta (Shared vs DG).
    """
    base_xpath = _build_base_xpath(device_group)
    xpath = f"{base_xpath}/{rulebase}/security/rules/entry[@name='{current_name}']"

    print(
        f"\n[INFO] Renombrando '{current_name}' → '{new_name}'\n"
        f"       XPath: {xpath}"
    )

    root = _api_get({
        "type": "config",
        "action": "rename",
        "xpath": xpath,
        "newname": new_name,
    })

    msg = root.findtext(".//msg") or "OK"
    print(f"[OK] Rename ejecutado correctamente. Respuesta: {msg}")

    # Nota: el cambio queda en el candidate config de Panorama (no committed).
    print(
        "\n[AVISO] El cambio está en el candidate config de Panorama.\n"
        "        Recuerda hacer commit en Panorama (y push al firewall si es necesario)."
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Renombra una regla de política de seguridad en Panorama "
            "usando su UUID como identificador."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--uuid",
        required=True,
        metavar="UUID",
        help="UUID de la regla (visible en Panorama o via API).",
    )
    parser.add_argument(
        "--device-group",
        required=True,
        metavar="DEVICE_GROUP",
        help="Nombre exacto del Device Group donde reside la regla.",
    )
    parser.add_argument(
        "--new-name",
        required=True,
        metavar="NUEVO_NOMBRE",
        help="Nuevo nombre que se asignará a la regla.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    print("=" * 60)
    print("  Panorama Rule Renamer")
    print("=" * 60)
    print(f"  Panorama  : {PAN_URL}")
    print(f"  UUID      : {args.uuid}")
    print(f"  Dev Group : {args.device_group}")
    print(f"  New Name  : {args.new_name}")
    print("=" * 60)
    print()

    # Paso 1: Resolver nombre actual por UUID
    current_name, rulebase = get_rule_name_by_uuid(args.uuid, args.device_group)

    # Paso 2: Renombrar
    rename_rule(args.device_group, rulebase, current_name, args.new_name)


if __name__ == "__main__":
    main()
