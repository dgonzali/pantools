#!/usr/bin/env python3
"""
objects_search.py
-----------------
Busca reglas de seguridad en Panorama que contengan objetos de tipo
address o address-group que incluyan una red IP determinada.

Flujo:
  1. Obtiene todos los Device Groups disponibles en Panorama (o usa el indicado).
  2. Recopila objetos address (ip-netmask) que coincidan con la red buscada,
     tanto en shared como en cada Device Group.
  3. Resuelve address-groups que referencien (directa o indirectamente)
     esos address objects.
  4. Escanea las pre-rulebase y post-rulebase de cada Device Group buscando
     reglas cuyo source o destination contenga alguno de esos objetos.

Uso:
  python objects_search.py --network 10.10.10.0/24
  python objects_search.py --network 10.10.10.5/32 --device-group MiDG
  python objects_search.py --network 10.10.10.0/24 --device-group shared
  python objects_search.py --network 10.10.10.0/24 --exact
  python objects_search.py --network 10.10.10.0/24 --output resultado.txt

Argumentos:
  --network       Red a buscar en formato IP/máscara (obligatorio).
  --device-group  Limitar la búsqueda a un Device Group concreto o 'shared'.
                  Si no se indica, se busca en todos.
  --exact         Solo coincidencias exactas de red (por defecto también busca
                  redes que contienen o están contenidas en la indicada).
  --output        Fichero donde escribir el resultado (además de stdout).
"""

import argparse
import ipaddress
import os
import sys
import urllib3
import xml.etree.ElementTree as ET
from collections import defaultdict

import requests
from dotenv import load_dotenv

# Suprimir warnings de SSL auto-firmado (habitual en Panorama)
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
        # Algunos endpoints devuelven success vacío en lugar de error
        msg = root.findtext(".//msg") or resp.text
        # Si el mensaje indica "object not found" lo tratamos como vacío, no error fatal
        if "Object Not Found" in msg or "object not found" in msg.lower():
            return root
        sys.exit(f"[ERROR] La API devolvió status='{status}': {msg}")

    return root


def _build_dg_addr_xpath(device_group: str) -> str:
    """XPath de la colección de address objects de un Device Group."""
    if device_group.lower() == "shared":
        return "/config/shared/address"
    return (
        "/config/devices/entry[@name='localhost.localdomain']"
        f"/device-group/entry[@name='{device_group}']/address"
    )


def _build_dg_addrgrp_xpath(device_group: str) -> str:
    """XPath de la colección de address-group objects de un Device Group."""
    if device_group.lower() == "shared":
        return "/config/shared/address-group"
    return (
        "/config/devices/entry[@name='localhost.localdomain']"
        f"/device-group/entry[@name='{device_group}']/address-group"
    )


def _build_rulebase_xpath(device_group: str, rulebase: str) -> str:
    """XPath de las reglas de seguridad (pre o post rulebase)."""
    if device_group.lower() == "shared":
        return f"/config/shared/{rulebase}/security/rules"
    return (
        "/config/devices/entry[@name='localhost.localdomain']"
        f"/device-group/entry[@name='{device_group}']/{rulebase}/security/rules"
    )


# ---------------------------------------------------------------------------
# Obtener Device Groups
# ---------------------------------------------------------------------------

def get_device_groups() -> list[str]:
    """Devuelve la lista de Device Groups configurados en Panorama."""
    xpath = "/config/devices/entry[@name='localhost.localdomain']/device-group"
    root = _api_get({"type": "config", "action": "get", "xpath": xpath})
    dgs = []
    for entry in root.findall(".//device-group/entry"):
        name = entry.attrib.get("name")
        if name:
            dgs.append(name)
    return dgs


# ---------------------------------------------------------------------------
# Coincidencia de redes
# ---------------------------------------------------------------------------

def _network_matches(candidate: str, target: ipaddress.IPv4Network | ipaddress.IPv6Network, exact: bool) -> bool:
    """
    Determina si la red candidata (string ip-netmask) tiene relación con la red target.

    Modos:
      exact=True  → solo si candidate == target
      exact=False → si candidate == target, overlaps, subnet o supernet de target
    """
    try:
        # Panorama puede almacenar un host solo ("10.10.10.1") sin máscara
        if "/" not in candidate:
            candidate = f"{candidate}/32" if "." in candidate else f"{candidate}/128"
        cand_net = ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        return False

    if exact:
        return cand_net == target

    # Coincide si: igual, la candidata contiene la target, o la target contiene la candidata
    return cand_net.overlaps(target)


# ---------------------------------------------------------------------------
# Recopilar address objects que coincidan
# ---------------------------------------------------------------------------

def get_matching_address_objects(
    scope: str,
    target: ipaddress.IPv4Network | ipaddress.IPv6Network,
    exact: bool,
) -> list[str]:
    """
    Devuelve los nombres de address objects en el scope indicado (DG o 'shared')
    cuyo ip-netmask coincide con la red objetivo.
    """
    xpath = _build_dg_addr_xpath(scope)
    root = _api_get({"type": "config", "action": "get", "xpath": xpath})

    matched = []
    for entry in root.findall(".//address/entry"):
        name = entry.attrib.get("name", "")
        ip_netmask = entry.findtext("ip-netmask") or ""
        if ip_netmask and _network_matches(ip_netmask.strip(), target, exact):
            matched.append(name)

    return matched


# ---------------------------------------------------------------------------
# Resolver address-groups (con recursividad)
# ---------------------------------------------------------------------------

def get_address_groups(scope: str) -> dict[str, list[str]]:
    """
    Devuelve un dict { group_name: [member1, member2, ...] } para el scope dado.
    Solo incluye miembros estáticos (static members), no dinámicos.
    """
    xpath = _build_dg_addrgrp_xpath(scope)
    root = _api_get({"type": "config", "action": "get", "xpath": xpath})

    groups: dict[str, list[str]] = {}
    for entry in root.findall(".//address-group/entry"):
        name = entry.attrib.get("name", "")
        members = [m.text for m in entry.findall(".//static/member") if m.text]
        groups[name] = members

    return groups


def resolve_matching_groups(
    all_groups: dict[str, list[str]],
    seed_objects: set[str],
) -> set[str]:
    """
    Dado un conjunto de address objects que coinciden (seed_objects),
    devuelve los address-groups que los referencian, de forma recursiva.

    Un grupo coincide si alguno de sus miembros es:
    - Un address object del conjunto semilla, o
    - Otro address-group que ya coincidió
    """
    matched_groups: set[str] = set()
    changed = True

    while changed:
        changed = False
        for gname, members in all_groups.items():
            if gname in matched_groups:
                continue
            for member in members:
                if member in seed_objects or member in matched_groups:
                    matched_groups.add(gname)
                    changed = True
                    break

    return matched_groups


# ---------------------------------------------------------------------------
# Buscar reglas que usen los objetos
# ---------------------------------------------------------------------------

def search_rules_in_scope(
    device_group: str,
    all_objects: set[str],
) -> list[dict]:
    """
    Busca en pre-rulebase y post-rulebase del device_group indicado
    las reglas de seguridad que usen alguno de los objetos en source o destination.

    Devuelve lista de dicts con info de cada regla coincidente.
    """
    results = []

    for rulebase in ("pre-rulebase", "post-rulebase"):
        xpath = _build_rulebase_xpath(device_group, rulebase)
        root = _api_get({"type": "config", "action": "get", "xpath": xpath})

        for rule_entry in root.findall(".//rules/entry"):
            rule_name = rule_entry.attrib.get("name", "")

            src_members = {m.text for m in rule_entry.findall(".//source/member") if m.text}
            dst_members = {m.text for m in rule_entry.findall(".//destination/member") if m.text}

            matched_src = src_members & all_objects
            matched_dst = dst_members & all_objects

            if matched_src or matched_dst:
                results.append({
                    "device_group": device_group,
                    "rulebase": rulebase,
                    "rule_name": rule_name,
                    "matched_source": sorted(matched_src),
                    "matched_destination": sorted(matched_dst),
                })

    return results


# ---------------------------------------------------------------------------
# Formateo de resultados
# ---------------------------------------------------------------------------

def format_results(
    network: str,
    scope_filter: str | None,
    addr_objects_by_scope: dict[str, list[str]],
    addr_groups_by_scope: dict[str, set[str]],
    rule_results: list[dict],
    exact: bool,
) -> str:
    lines = []
    sep = "=" * 70

    lines.append(sep)
    lines.append("  Panorama Objects Search — Resultados")
    lines.append(sep)
    lines.append(f"  Red buscada  : {network}")
    lines.append(f"  Modo         : {'Coincidencia exacta' if exact else 'Overlapping (contiene / está contenida)'}")
    lines.append(f"  Ámbito       : {scope_filter if scope_filter else 'Todos los Device Groups + shared'}")
    lines.append(sep)
    lines.append("")

    # --- Objetos encontrados ---
    lines.append("── OBJETOS ADDRESS COINCIDENTES ──────────────────────────────────")
    any_addr = False
    for scope, objs in addr_objects_by_scope.items():
        if objs:
            any_addr = True
            lines.append(f"  [{scope}]")
            for obj in sorted(objs):
                lines.append(f"    • {obj}")
    if not any_addr:
        lines.append("  (ninguno)")
    lines.append("")

    # --- Address-groups ---
    lines.append("── ADDRESS-GROUPS QUE LOS INCLUYEN ───────────────────────────────")
    any_grp = False
    for scope, grps in addr_groups_by_scope.items():
        if grps:
            any_grp = True
            lines.append(f"  [{scope}]")
            for grp in sorted(grps):
                lines.append(f"    • {grp}")
    if not any_grp:
        lines.append("  (ninguno)")
    lines.append("")

    # --- Reglas ---
    lines.append("── REGLAS DE SEGURIDAD AFECTADAS ─────────────────────────────────")
    if not rule_results:
        lines.append("  (ninguna regla encontrada)")
    else:
        # Agrupar por device_group
        by_dg: dict[str, list[dict]] = defaultdict(list)
        for r in rule_results:
            by_dg[r["device_group"]].append(r)

        for dg, rules in sorted(by_dg.items()):
            lines.append(f"\n  Device Group: {dg}")
            lines.append("  " + "-" * 50)
            for r in rules:
                lines.append(f"  [{r['rulebase']}] {r['rule_name']}")
                if r["matched_source"]:
                    lines.append(f"      Source → {', '.join(r['matched_source'])}")
                if r["matched_destination"]:
                    lines.append(f"      Destination → {', '.join(r['matched_destination'])}")

    lines.append("")
    lines.append(sep)
    lines.append(f"  Total reglas encontradas: {len(rule_results)}")
    lines.append(sep)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Busca reglas de seguridad en Panorama que referencien objetos "
            "(address / address-group) que incluyan una red IP determinada."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--network",
        required=True,
        metavar="IP/MASK",
        help="Red a buscar, formato CIDR. Ej: 10.10.10.0/24 o 192.168.1.5/32",
    )
    parser.add_argument(
        "--device-group",
        metavar="DEVICE_GROUP",
        default=None,
        help=(
            "Limitar la búsqueda a un Device Group concreto. "
            "Usa 'shared' para buscar solo en objetos compartidos. "
            "Si no se indica, se busca en todos los Device Groups y shared."
        ),
    )
    parser.add_argument(
        "--exact",
        action="store_true",
        default=False,
        help=(
            "Solo devuelve objetos cuya red sea exactamente la indicada. "
            "Por defecto también incluye redes que se solapan (supernets / subnets)."
        ),
    )
    parser.add_argument(
        "--output",
        metavar="FICHERO",
        default=None,
        help="Fichero de texto donde guardar el resultado (además de mostrarlo en pantalla).",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()

    # Validar la red
    try:
        target_network = ipaddress.ip_network(args.network, strict=False)
    except ValueError:
        sys.exit(f"[ERROR] '{args.network}' no es una red IP válida. Usa formato CIDR (ej: 10.0.0.0/8).")

    scope_filter: str | None = args.device_group

    print(f"\n[INFO] Conectando a Panorama: {PAN_URL}")
    print(f"[INFO] Red objetivo: {target_network}  (modo: {'exacto' if args.exact else 'overlapping'})")
    if scope_filter:
        print(f"[INFO] Ámbito limitado a: {scope_filter}")
    else:
        print("[INFO] Ámbito: todos los Device Groups + shared")

    # ------------------------------------------------------------------
    # Determinar los scopes a analizar
    # ------------------------------------------------------------------
    if scope_filter:
        scopes_addr = [scope_filter]           # solo el scope indicado para address objects
        scopes_rules = []
        if scope_filter.lower() != "shared":
            scopes_rules = [scope_filter]      # shared no tiene rulebases propias en Panorama
    else:
        print("\n[INFO] Obteniendo Device Groups de Panorama...")
        dg_list = get_device_groups()
        if not dg_list:
            sys.exit("[ERROR] No se encontraron Device Groups en Panorama.")
        print(f"[INFO] Device Groups encontrados: {', '.join(dg_list)}")
        scopes_addr = ["shared"] + dg_list
        scopes_rules = dg_list   # las rulebases están bajo cada DG, no bajo shared

    # ------------------------------------------------------------------
    # Paso 1: Recopilar address objects coincidentes por scope
    # ------------------------------------------------------------------
    print("\n[INFO] Buscando address objects coincidentes...")
    addr_objects_by_scope: dict[str, list[str]] = {}
    all_matching_addr_objects: set[str] = set()

    for scope in scopes_addr:
        objs = get_matching_address_objects(scope, target_network, args.exact)
        addr_objects_by_scope[scope] = objs
        all_matching_addr_objects.update(objs)
        if objs:
            print(f"  [{scope}] {len(objs)} objeto(s): {', '.join(objs)}")
        else:
            print(f"  [{scope}] ningún objeto encontrado")

    # ------------------------------------------------------------------
    # Paso 2: Resolver address-groups que los incluyen (por scope)
    # ------------------------------------------------------------------
    print("\n[INFO] Resolviendo address-groups...")
    addr_groups_by_scope: dict[str, set[str]] = {}
    all_matching_objects: set[str] = set(all_matching_addr_objects)

    for scope in scopes_addr:
        all_groups = get_address_groups(scope)
        matched_grps = resolve_matching_groups(all_groups, all_matching_addr_objects)
        addr_groups_by_scope[scope] = matched_grps
        all_matching_objects.update(matched_grps)
        if matched_grps:
            print(f"  [{scope}] {len(matched_grps)} grupo(s): {', '.join(sorted(matched_grps))}")
        else:
            print(f"  [{scope}] ningún address-group encontrado")

    if not all_matching_objects:
        print("\n[WARN] No se encontraron objetos coincidentes. No hay reglas que buscar.")
        output = format_results(
            args.network, scope_filter,
            addr_objects_by_scope, addr_groups_by_scope, [], args.exact
        )
        print("\n" + output)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output)
            print(f"\n[INFO] Resultado guardado en: {args.output}")
        return

    print(f"\n[INFO] Total objetos a buscar en reglas: {len(all_matching_objects)}")
    print(f"       {', '.join(sorted(all_matching_objects))}")

    # ------------------------------------------------------------------
    # Paso 3: Buscar reglas en cada Device Group
    # ------------------------------------------------------------------
    print("\n[INFO] Buscando en rulebases de seguridad...")
    all_rule_results: list[dict] = []

    for dg in scopes_rules:
        print(f"  Analizando Device Group: {dg}...")
        rules = search_rules_in_scope(dg, all_matching_objects)
        all_rule_results.extend(rules)
        if rules:
            print(f"    → {len(rules)} regla(s) encontrada(s)")
        else:
            print("    → sin coincidencias")

    # ------------------------------------------------------------------
    # Paso 4: Formatear y mostrar resultados
    # ------------------------------------------------------------------
    output = format_results(
        args.network, scope_filter,
        addr_objects_by_scope, addr_groups_by_scope,
        all_rule_results, args.exact,
    )

    print("\n" + output)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"\n[INFO] Resultado guardado en: {args.output}")


if __name__ == "__main__":
    main()
