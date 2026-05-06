#!/usr/bin/env python3
"""
04_Commit-all_cloudaws.py
--------------------------
Realiza un Commit-All a los Cloud Device Groups de Palo Alto Cloud NGFW for AWS
gestionados desde Panorama.

Flujo:
  1. Consulta cada región AWS configurada para detectar firewalls desplegados.
  2. Recoge los device_group_name de las regiones con firewalls activos.
  3. Muestra un resumen y solicita confirmación al usuario.
  4. Lanza el Commit-All a cada Cloud Device Group (uno a uno, con pausa configurable).
  5. Monitoriza el estado del push hasta que finalice (Success / Error).
  6. Muestra un resumen final con los resultados.

Requisitos (.env):
  PAN_URL=https://<panorama-ip-o-fqdn>
  PAN_API_KEY=<api-key>
"""

import json
import os
import sys
import time
import xml.etree.ElementTree as ET

import requests
import urllib3
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Configuración inicial
# ---------------------------------------------------------------------------

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

PAN_URL     = os.getenv("PAN_URL_CLOUD", "").rstrip("/")
PAN_API_KEY = os.getenv("PAN_API_KEY_CLOUD", "")

if not PAN_URL or not PAN_API_KEY:
    sys.exit("[ERROR] PAN_URL y PAN_API_KEY deben estar definidas en el fichero .env")

# ---------------------------------------------------------------------------
# Parámetros configurables
# ---------------------------------------------------------------------------
"""
# Regiones AWS donde buscar Cloud NGFWs desplegados
AWS_REGIONS = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-central-1",
    "eu-south-1",
    "eu-south-2",
    "eu-north-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-south-1",
    "sa-east-1",
    "ca-central-1",
    "me-south-1",
    "af-south-1",
]
"""
AWS_REGIONS = [
    "us-west-2",
    "eu-west-1",
]
# Pausa (segundos) entre peticiones de Commit-All consecutivas
COMMIT_DELAY_SECONDS = 2

# Intervalo (segundos) entre consultas de estado mientras el commit está en curso
POLL_INTERVAL_SECONDS = 30

# Timeout de conexión HTTP
TIMEOUT = 60


# ---------------------------------------------------------------------------
# Helpers de API
# ---------------------------------------------------------------------------

def _api_get_raw(params: dict) -> requests.Response:
    """Realiza una petición GET a la API XML de Panorama y devuelve la Response."""
    params["key"] = PAN_API_KEY
    try:
        resp = requests.get(
            f"{PAN_URL}/api/",
            params=params,
            verify=False,
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
    except requests.exceptions.Timeout:
        raise RuntimeError("Timeout al conectar con Panorama")
    except requests.RequestException as exc:
        raise RuntimeError(f"Error de conexión con Panorama: {exc}")
    return resp


def _api_get(params: dict) -> ET.Element:
    """Realiza una petición GET y devuelve el XML parseado. Lanza RuntimeError si no es 'success'."""
    resp = _api_get_raw(params)
    root = ET.fromstring(resp.text)
    status = root.attrib.get("status", "")
    if status != "success":
        msg = root.findtext(".//msg") or resp.text[:300]
        raise RuntimeError(f"La API devolvió status='{status}': {msg}")
    return root


# ---------------------------------------------------------------------------
# Consulta de recursos Cloud NGFW por región
# ---------------------------------------------------------------------------

def get_cngfw_resources(region: str) -> list[dict]:
    """
    Consulta los Cloud NGFW desplegados en una región AWS concreta.
    Devuelve una lista de dicts con los campos del entry (vacía si no hay firewalls).
    """
    cmd = (
        "<show><plugins><aws><cngfw-resources>"
        "<tenant-name>All</tenant-name>"
        f"<region>{region}</region>"
        "<tenant-id>All</tenant-id>"
        "</cngfw-resources></aws></plugins></show>"
    )
    try:
        root = _api_get({"type": "op", "cmd": cmd})
    except RuntimeError as exc:
        print(f"  [WARN] Error consultando región {region}: {exc}")
        return []

    # El resultado está embebido como JSON dentro del elemento <msg>
    msg_text = root.findtext(".//msg") or ""
    if not msg_text:
        return []

    try:
        data = json.loads(msg_text)
    except json.JSONDecodeError:
        print(f"  [WARN] No se pudo parsear el JSON de la región {region}")
        return []

    result = data.get("result", {})
    entries = result.get("entry", "")

    # Cuando no hay firewalls, entry viene como cadena vacía ""
    if not entries or entries == "":
        return []

    # Puede ser un dict (un solo entry) o una lista
    if isinstance(entries, dict):
        entries = [entries]

    return entries


# ---------------------------------------------------------------------------
# Descubrimiento de Cloud Device Groups con firewalls activos
# ---------------------------------------------------------------------------

def discover_cloud_device_groups() -> dict[str, list[dict]]:
    """
    Recorre todas las regiones AWS configuradas y recoge los Cloud Device Groups
    donde hay firewalls desplegados.

    Devuelve un dict:  { region -> [entry_dict, ...] }
    Solo se incluyen regiones con al menos un firewall.
    """
    print()
    print("=" * 70)
    print("  FASE 1 — Descubrimiento de Cloud NGFWs por región AWS")
    print("=" * 70)
    print(f"  Panorama : {PAN_URL}")
    print(f"  Regiones a consultar: {len(AWS_REGIONS)}")
    print("=" * 70)
    print()

    active: dict[str, list[dict]] = {}

    for region in AWS_REGIONS:
        print(f"  [>] Consultando región: {region} ...", end=" ", flush=True)
        entries = get_cngfw_resources(region)
        if entries:
            print(f"✓  {len(entries)} firewall(s) encontrado(s)")
            active[region] = entries
        else:
            print("—  Sin firewalls desplegados")

    return active


# ---------------------------------------------------------------------------
# Commit-All a un Cloud Device Group
# ---------------------------------------------------------------------------

def send_commit_all(device_group_name: str) -> str:
    """
    Envía el Commit-All a un Cloud Device Group concreto.
    Devuelve el job-id si se encoló correctamente, o "" en caso de error.
    """
    cmd = (
        "<commit-all><shared-policy><device-group>"
        f'<entry name="{device_group_name}"/>'
        "</device-group></shared-policy></commit-all>"
    )
    try:
        root = _api_get({"type": "commit", "action": "all", "cmd": cmd})
    except RuntimeError as exc:
        print(f"  [ERROR] Commit-All fallido para '{device_group_name}': {exc}")
        return ""

    job_id = root.findtext(".//job") or ""
    return job_id


# ---------------------------------------------------------------------------
# Monitorización del estado del push
# ---------------------------------------------------------------------------

def monitor_commit_status(regions_entries: dict[str, list[dict]]) -> list[dict]:
    """
    Monitoriza el estado del Commit-All consultando de nuevo la API de recursos
    por región, hasta que ningún entry tenga 'last_committed_state' == 'Committing'.

    Devuelve la lista final de resultados: [{ region, entries }]
    """
    print()
    print("=" * 70)
    print("  FASE 3 — Monitorización del estado del Commit-All")
    print("=" * 70)
    print(f"  Consultando estado cada {POLL_INTERVAL_SECONDS}s hasta finalización...")
    print()

    # Construimos el conjunto de regiones a monitorizar
    regions_to_check = list(regions_entries.keys())

    attempt = 0
    while True:
        attempt += 1
        print(f"  [Intento {attempt}] {time.strftime('%H:%M:%S')} — Consultando estado del push...")

        all_done = True
        current_state: dict[str, list[dict]] = {}

        for region in regions_to_check:
            entries = get_cngfw_resources(region)
            current_state[region] = entries

            committing = [
                e for e in entries
                if e.get("last_committed_state", "").lower() == "committing"
            ]
            if committing:
                all_done = False
                dgs = ", ".join(e.get("device_group_name", "?") for e in committing)
                print(f"    [{region}] ⏳ Commit en curso: {dgs}")
            else:
                for e in entries:
                    state = e.get("last_committed_state", "?")
                    dg    = e.get("device_group_name", "?")
                    ts    = e.get("last_committed_message", "")
                    icon  = "✓" if state.lower() == "success" else "✗"
                    print(f"    [{region}] {icon} {dg} → {state}  ({ts})")

        if all_done:
            print()
            print("  [OK] Todos los commits han finalizado.")
            return [{"region": r, "entries": current_state[r]} for r in regions_to_check]

        print(f"  ⏳ Siguiente comprobación en {POLL_INTERVAL_SECONDS}s ...")
        time.sleep(POLL_INTERVAL_SECONDS)


# ---------------------------------------------------------------------------
# Presentación de resultados finales
# ---------------------------------------------------------------------------

def print_final_summary(final_states: list[dict]) -> None:
    """Muestra el resumen final de los commits realizados."""
    print()
    print("=" * 70)
    print("  RESUMEN FINAL — Commit-All Cloud NGFW for AWS")
    print("=" * 70)

    total_dgs  = 0
    total_ok   = 0
    total_fail = 0

    for item in final_states:
        region  = item["region"]
        entries = item["entries"]
        print(f"\n  Región: {region}")
        print(f"  {'Device Group':<40} {'Estado':<15} {'Último Commit'}")
        print(f"  {'-'*40} {'-'*15} {'-'*30}")

        for e in entries:
            dg    = e.get("device_group_name", "?")
            state = e.get("last_committed_state", "?")
            ts    = e.get("last_committed_message", "")
            icon  = "✓" if state.lower() == "success" else "✗"
            print(f"  {icon} {dg:<39} {state:<15} {ts}")
            total_dgs += 1
            if state.lower() == "success":
                total_ok += 1
            else:
                total_fail += 1

    print()
    print("=" * 70)
    print(f"  Total Device Groups procesados : {total_dgs}")
    print(f"  Commits exitosos               : {total_ok}")
    print(f"  Commits con error/incidencia   : {total_fail}")
    print("=" * 70)
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    # ---- FASE 1: Descubrimiento ----
    active_regions = discover_cloud_device_groups()

    if not active_regions:
        print()
        print("[INFO] No se encontraron Cloud NGFWs desplegados en ninguna región.")
        print("[INFO] No hay nada que commitear. Saliendo.")
        sys.exit(0)

    # Construimos la lista de device groups únicos (puede haber varios por región)
    # Mantenemos mapeo region -> [dg_names] para la monitorización posterior
    dg_to_regions: dict[str, list[str]] = {}
    for region, entries in active_regions.items():
        for e in entries:
            dg = e.get("device_group_name", "")
            if dg:
                dg_to_regions.setdefault(dg, []).append(region)

    unique_dgs = list(dg_to_regions.keys())

    # ---- Resumen pre-commit ----
    print()
    print("=" * 70)
    print("  FASE 2 — Commit-All a Cloud Device Groups")
    print("=" * 70)
    print()
    print(f"  Se realizará Commit-All a los siguientes {len(unique_dgs)} Device Group(s):")
    print()
    for dg in unique_dgs:
        regions_str = ", ".join(dg_to_regions[dg])
        print(f"    • {dg}  (región/es: {regions_str})")
    print()
    print(f"  Pausa entre commits : {COMMIT_DELAY_SECONDS}s")
    print()

    # ---- Confirmación ----
    try:
        confirm = input("  ¿Deseas proceder con el Commit-All? [s/N]: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print("\n[INFO] Operación cancelada por el usuario.")
        sys.exit(0)

    if confirm not in ("s", "si", "sí", "yes", "y"):
        print("[INFO] Operación cancelada por el usuario.")
        sys.exit(0)

    print()

    # ---- Envío de Commit-All ----
    job_results: list[dict] = []
    for i, dg in enumerate(unique_dgs, start=1):
        print(f"  [{i}/{len(unique_dgs)}] Enviando Commit-All → '{dg}' ...", end=" ", flush=True)
        job_id = send_commit_all(dg)
        if job_id:
            print(f"✓  Job ID: {job_id}")
        else:
            print("✗  No se obtuvo Job ID (ver error arriba)")
        job_results.append({"dg": dg, "job_id": job_id})

        if i < len(unique_dgs):
            print(f"     (esperando {COMMIT_DELAY_SECONDS}s antes del siguiente commit...)")
            time.sleep(COMMIT_DELAY_SECONDS)

    print()
    print("  [OK] Todas las peticiones de Commit-All han sido enviadas.")

    # ---- FASE 3: Monitorización ----
    # Esperamos un momento antes de empezar a consultar el estado
    print(f"\n  Esperando {POLL_INTERVAL_SECONDS}s antes de iniciar la monitorización...")
    time.sleep(POLL_INTERVAL_SECONDS)

    final_states = monitor_commit_status(active_regions)

    # ---- FASE 4: Resumen final ----
    print_final_summary(final_states)


if __name__ == "__main__":
    main()
