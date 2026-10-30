import os
from dotenv import load_dotenv
from panos.panorama import Panorama
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

# Cargar las variables del archivo .env
load_dotenv()

PAN_URL = os.getenv("PAN_URL")
PAN_API_KEY = os.getenv("PAN_API_KEY")

def limpiar_hostname(url_o_host):
    """Extrae únicamente el dominio o IP limpio si se pasa una URL completa."""
    if not url_o_host:
        return ""
    if "://" in url_o_host:
        parsed = urlparse(url_o_host)
        return parsed.hostname or parsed.path
    return url_o_host.strip("/")

def obtener_commits_en_cola():
    if not PAN_URL or not PAN_API_KEY:
        print("❌ Error: Asegúrate de definir PAN_URL y PAN_API_KEY en tu archivo .env")
        return None

    hostname = limpiar_hostname(PAN_URL)

    try:
        # 1. Conectar a Panorama
        panorama = Panorama(hostname=hostname, api_key=PAN_API_KEY)
        
        # 2. Ejecutar directamente el comando CLI (pan-os-python se encarga del formato)
        response = panorama.op("show jobs all")
        
        # 3. Parsear la respuesta para contar los commits en cola
        pending_commits = 0
        
        # pan-os-python puede devolver un string XML o un objeto Element de ElementTree
        if isinstance(response, str):
            root = ET.fromstring(response)
        else:
            root = response

        # Buscar todos los elementos <job> en la respuesta
        jobs = root.findall(".//job")
        
        for job in jobs:
            job_type = job.find("type")
            status = job.find("status")
            
            # Filtrar jobs de tipo commit y estado PEND (Pending) o ACT (Active)
            if job_type is not None and job_type.text and "commit" in job_type.text.lower():
                if status is not None and status.text in ["PEND", "ACT"]:
                    pending_commits += 1

        print(f"📊 Número de commits en cola / activos actualmente: {pending_commits}")
        return pending_commits

    except Exception as e:
        print(f"❌ Error al comunicarse con Panorama: {e}")
        return None

if __name__ == "__main__":
    obtener_commits_en_cola()