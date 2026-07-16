# Panorama API Scripts

Colección de scripts Python para automatizar tareas en **Palo Alto Networks Panorama** vía API XML.

---

## Scripts disponibles

| Script | Descripción |
|--------|-------------|
| [`01-rule_renamer.py`](#1-rule-renamer) | Renombra reglas de seguridad usando su UUID |
| [`02-objects_search.py`](#2-objects-search) | Busca objetos de red (address/group) en reglas de seguridad por IP/red |
| [`03-pan_device_admins.py`](#3-pan-device-admins) | Audita los administradores y roles de los firewalls conectados |
| [`04_Commit-all_cloudaws.py`](#4-commit-all-cloud-ngfw-aws) | Realiza Commit-All a Cloud Device Groups de Cloud NGFW for AWS |
| [`05_pan_policy_test.py`](#5-pan-policy-test) | Simula qué regla de seguridad aplicaría a un flujo de tráfico determinado |

---

## Requisitos comunes

- Python 3.8+
- Acceso de red a Panorama (puerto 443)
- API Key con los permisos adecuados

### Instalación de dependencias

```bash
pip install -r requirements.txt
```

**Dependencias:**

| Paquete | Uso |
|---------|-----|
| `requests` | Llamadas HTTP a la API de Panorama |
| `python-dotenv` | Carga de variables de entorno desde `.env` |
| `urllib3` | Supresión de warnings SSL (certificado auto-firmado) |

---

## Configuración

Crea (o edita) el fichero `.env` en el directorio del proyecto:

```env
PAN_URL=https://<ip-o-hostname-panorama>
PAN_API_KEY=<tu-api-key>
```

> La API Key se puede obtener desde Panorama en **Device → Administrators** o vía API:
> ```
> GET /api/?type=keygen&user=<usuario>&password=<password>
> ```

---

## Estructura del proyecto

```
Pantools/
├── .env                        # Credenciales de Panorama (no subir a git)
├── 01-rule_renamer.py          # Renombrador de reglas por UUID
├── 02-objects_search.py        # Buscador de objetos por IP/red en reglas
├── 03-pan_device_admins.py     # Auditor de administradores en firewalls
├── 04_Commit-all_cloudaws.py   # Commit-All a Cloud Device Groups AWS
├── 05_pan_policy_test.py       # Simulador de policy test por Device Group
├── debug.txt                   # Log de debug (solo si se usa --debug en el script 03)
├── requirements.txt            # Dependencias Python
└── README.md                   # Este fichero
```

---

---

# 1. Rule Renamer

Script Python para renombrar reglas de política de seguridad en Panorama usando el **UUID** de la regla como identificador de entrada.

## ¿Por qué este script?

La API XML de PAN-OS/Panorama expone el comando `rename`, pero **este comando requiere el nombre actual de la regla**, no su UUID. Sin embargo, en muchos flujos de automatización el identificador disponible es el UUID (inmutable, único globalmente).

Este script resuelve el problema en dos pasos:

1. **Resolver UUID → Nombre actual** mediante una consulta `get` con un predicado XPath sobre el atributo `@uuid`.
2. **Renombrar** la regla con el comando `rename` usando el nombre obtenido en el paso anterior.

## Flujo de ejecución

```
INPUT: uuid | device-group | new-name
          │
          ▼
┌─────────────────────────────────────┐
│  Paso 1: GET (config/get)           │
│  Busca la regla por @uuid           │
│  → Obtiene el nombre actual         │
│  → Detecta pre o post rulebase      │
└─────────────────┬───────────────────┘
                  │ nombre actual + rulebase
                  ▼
┌─────────────────────────────────────┐
│  Paso 2: GET (config/rename)        │
│  Renombra usando el nombre actual   │
│  → Aplica en candidate config       │
└─────────────────────────────────────┘
          │
          ▼
OUTPUT: Confirmación + aviso de commit pendiente
```

## Llamadas API

### Paso 1 — Buscar la regla por UUID

| Campo | Valor |
|-------|-------|
| Método | `GET` |
| Endpoint | `/api/` |
| `type` | `config` |
| `action` | `get` |
| `xpath` | Ver abajo |

**XPath — Device Group normal (pre-rulebase):**
```
/config/devices/entry[@name='localhost.localdomain']
  /device-group/entry[@name='{DEVICE_GROUP}']
    /pre-rulebase/security/rules/entry[@uuid='{UUID}']
```

**XPath — Shared (pre-rulebase):**
```
/config/shared
  /pre-rulebase/security/rules/entry[@uuid='{UUID}']
```

> ⚠️ Las reglas del nivel **Shared** en Panorama **no** se almacenan bajo
> `/device-group/entry[@name='Shared']`, sino directamente bajo `/config/shared/`.
> El script detecta automáticamente este caso cuando `--device-group Shared`.

Si no se encuentra en `pre-rulebase`, se reintenta con `post-rulebase` en la misma ruta base.

**Respuesta esperada (XML):**
```xml
<response status="success">
  <result>
    <entry name="Allow-HTTP-Viejo" uuid="12345678-abcd-...">
      ...
    </entry>
  </result>
</response>
```

### Paso 2 — Renombrar la regla

| Campo | Valor |
|-------|-------|
| Método | `GET` |
| Endpoint | `/api/` |
| `type` | `config` |
| `action` | `rename` |
| `xpath` | Ver abajo |
| `newname` | Nuevo nombre de la regla |

**XPath — Device Group normal:**
```
/config/devices/entry[@name='localhost.localdomain']
  /device-group/entry[@name='{DEVICE_GROUP}']
    /{pre-rulebase|post-rulebase}/security/rules/entry[@name='{NOMBRE_ACTUAL}']
```

**XPath — Shared:**
```
/config/shared
  /{pre-rulebase|post-rulebase}/security/rules/entry[@name='{NOMBRE_ACTUAL}']
```

**Respuesta esperada (XML):**
```xml
<response status="success">
  <msg>command succeeded</msg>
</response>
```

> ⚠️ **Importante:** El cambio se aplica únicamente en el **candidate config** de Panorama. Es necesario hacer **commit** en Panorama y, opcionalmente, un **push** a los firewalls gestionados.

## Uso

```bash
python 01-rule_renamer.py \
  --uuid "<UUID-DE-LA-REGLA>" \
  --device-group "<NOMBRE-DEL-DEVICE-GROUP>" \
  --new-name "<NUEVO-NOMBRE>"
```

### Parámetros

| Parámetro | Descripción |
|-----------|-------------|
| `--uuid` | UUID de la regla (formato `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) |
| `--device-group` | Nombre exacto del Device Group en Panorama |
| `--new-name` | Nuevo nombre que se aplicará a la regla |

### Ejemplo

```bash
python 01-rule_renamer.py \
  --uuid "a1b2c3d4-e5f6-7890-abcd-ef1234567890" \
  --device-group "DG-PRODUCCION" \
  --new-name "Allow-HTTP-Servidores-Web"
```

### Salida esperada

```
============================================================
  Panorama Rule Renamer
============================================================
  Panorama  : https://panorama.ejemplo.com
  UUID      : a1b2c3d4-e5f6-7890-abcd-ef1234567890
  Dev Group : DG-PRODUCCION
  New Name  : Allow-HTTP-Servidores-Web
============================================================

[INFO] Buscando regla en pre-rulebase con XPath: ...
[INFO] Regla encontrada en pre-rulebase: 'Allow-HTTP-Viejo'

[INFO] Renombrando 'Allow-HTTP-Viejo' → 'Allow-HTTP-Servidores-Web'
       XPath: /config/devices/entry[...]/pre-rulebase/security/rules/entry[@name='Allow-HTTP-Viejo']
[OK] Rename ejecutado correctamente. Respuesta: command succeeded

[AVISO] El cambio está en el candidate config de Panorama.
        Recuerda hacer commit en Panorama (y push al firewall si es necesario).
```

---

---

# 2. Objects Search

Script Python para **buscar reglas de seguridad en Panorama** que referencien objetos de tipo `address` o `address-group` que incluyan (o se solapen con) una red IP determinada.

## Caso de uso

Panorama no ofrece de forma nativa un buscador de objetos por red IP que cruce los resultados con las reglas que los usan. Este script cubre ese hueco:

1. Localiza todos los `address objects` cuyo `ip-netmask` coincide con la red buscada.
2. Resuelve de forma recursiva los `address-groups` que los contienen.
3. Escanea las `pre-rulebase` y `post-rulebase` de todos (o un subset) de Device Groups e indica en qué reglas aparece cada objeto, tanto en `source` como en `destination`.

## Uso

```bash
# Buscar la red en todos los Device Groups + shared (modo overlapping por defecto)
python 02-objects_search.py --network 10.10.10.0/24

# Limitar la búsqueda a un Device Group concreto
python 02-objects_search.py --network 10.10.10.0/24 --device-group MiDeviceGroup

# Buscar solo en los objetos compartidos (shared)
python 02-objects_search.py --network 10.10.10.5/32 --device-group shared

# Modo exacto: solo objetos cuya red sea exactamente la indicada
python 02-objects_search.py --network 10.10.10.0/24 --exact

# Guardar el resultado en un fichero además de mostrarlo en pantalla
python 02-objects_search.py --network 10.10.10.0/24 --output resultado.txt
```

## Argumentos

| Argumento | Obligatorio | Descripción |
|-----------|-------------|-------------|
| `--network IP/MASK` | ✅ | Red en formato CIDR: `10.0.0.0/8`, `192.168.1.1/32`, etc. |
| `--device-group DG` | ❌ | Limitar el ámbito. Sin este argumento se busca en **todos** los DG y shared. Usa `shared` para solo objetos compartidos. |
| `--exact` | ❌ | Solo coincidencias exactas de red. Por defecto también incluye supernets y subnets. |
| `--output FILE` | ❌ | Fichero de texto donde guardar el resultado adicionalmente. |

## Modo de coincidencia (overlapping vs exacto)

| Modo | Qué incluye |
|------|-------------|
| **Overlapping** (por defecto) | Objetos cuya red es exactamente la buscada, la contiene o está contenida en ella. Ej: buscando `10.10.10.0/24` también aparece `10.10.0.0/16` (supernet) y `10.10.10.128/25` (subnet). |
| **Exacto** (`--exact`) | Solo objetos que tienen exactamente la misma red. |

## Ejemplo de salida

```
======================================================================
  Panorama Objects Search — Resultados
======================================================================
  Red buscada  : 10.10.10.0/24
  Modo         : Overlapping (contiene / está contenida)
  Ámbito       : Todos los Device Groups + shared
======================================================================

── OBJETOS ADDRESS COINCIDENTES ──────────────────────────────────
  [shared]
    • net-10.10.10.0_24
  [DG-PRODUCCION]
    • host-10.10.10.5

── ADDRESS-GROUPS QUE LOS INCLUYEN ───────────────────────────────
  [shared]
    • grp-redes-internas
  [DG-PRODUCCION]
    • grp-servidores-prod

── REGLAS DE SEGURIDAD AFECTADAS ─────────────────────────────────

  Device Group: DG-PRODUCCION
  --------------------------------------------------
  [pre-rulebase] Allow-HTTP-Interno
      Source → grp-redes-internas
  [pre-rulebase] Block-SSH-Externo
      Destination → host-10.10.10.5, grp-servidores-prod

======================================================================
  Total reglas encontradas: 2
======================================================================
```

---

---

# 3. Pan Device Admins

Script Python para obtener los **usuarios administradores y sus roles** configurados en todos los firewalls conectados a Panorama, utilizando Panorama como **proxy de API** (parámetro `target=<serial>`).

## Flujo de ejecución

```
 INPUT: [--sn | --device-name | --device-group | (ninguno)]
            |
            v
 +-----------------------------------------------+
 | Paso 1: show devices connected (op command)   |
 | Obtiene lista de firewalls conectados          |
 +-----------------------------------------------+
            |
            v
 +-----------------------------------------------+
 | Paso 2: config get device-group/entry         |
 | Construye mapa serial -> [Device Groups]       |
 +-----------------------------------------------+
            |
            v
 +-----------------------------------------------+
 | Paso 3: Filtra por --sn / --device-name /     |
 |         --device-group (o mantiene todos)      |
 +-----------------------------------------------+
            |
     Para cada dispositivo
            |
            v
 +-----------------------------------------------+
 | Paso 4: config get /config/mgt-config/users   |
 |         con target=<serial> (via Panorama)     |
 |         Extrae usuarios + tipo de rol          |
 +-----------------------------------------------+
            |
            v
 OUTPUT: Tabla por dispositivo en consola
         + CSV consolidado (si --output)
```

## Llamadas API

### Paso 1 — Dispositivos conectados

| Campo | Valor |
|-------|-------|
| `type` | `op` |
| `cmd` | `<show><devices><connected/></devices></show>` |

### Paso 2 — Mapa de Device Groups

| Campo | Valor |
|-------|-------|
| `type` | `config` |
| `action` | `get` |
| `xpath` | `/config/devices/entry[@name='localhost.localdomain']/device-group/entry` |

> Esta llamada es necesaria porque el comando operacional `show devices connected` no incluye la pertenencia a Device Groups en su respuesta XML. El script la obtiene separadamente de la configuración de Panorama.

### Paso 3 — Administradores del dispositivo (vía proxy)

| Campo | Valor |
|-------|-------|
| `type` | `config` |
| `action` | `get` |
| `xpath` | `/config/mgt-config/users/entry` |
| `target` | Serial number del firewall |

El parámetro `target` hace que Panorama actúe como proxy y enruta la petición directamente al firewall con ese serial number, sin necesidad de acceder directamente a cada equipo.

**Respuesta esperada (XML):**
```xml
<response status="success">
  <result>
    <entry name="admin">
      <permissions>
        <role-based>
          <superuser/>
        </role-based>
      </permissions>
    </entry>
    <entry name="readonly">
      <permissions>
        <role-based>
          <superreader/>
        </role-based>
      </permissions>
    </entry>
    <entry name="operador">
      <permissions>
        <role-based>
          <custom>
            <profile>mi-perfil-personalizado</profile>
          </custom>
        </role-based>
      </permissions>
    </entry>
  </result>
</response>
```

## Uso

```bash
# Todos los firewalls conectados
python 03-pan_device_admins.py

# Solo un firewall por serial number
python 03-pan_device_admins.py --sn 007957000675956

# Solo un firewall por nombre de host
python 03-pan_device_admins.py --device-name FW-MADRID-01

# Solo los firewalls de un Device Group
python 03-pan_device_admins.py --device-group DG-PRODUCCION

# Cualquier filtro + exportar a CSV
python 03-pan_device_admins.py --device-group DG-PRODUCCION --output admins.csv

# Activar modo debug (genera debug.txt)
python 03-pan_device_admins.py --debug

# Combinar debug con cualquier otro argumento
python 03-pan_device_admins.py --device-group DG-PRODUCCION --output admins.csv --debug
```

### Argumentos

| Argumento | Descripción |
|-----------|-------------|
| *(ninguno)* | Consulta todos los firewalls conectados a Panorama |
| `--sn SERIAL` | Limita la consulta al firewall con ese serial number |
| `--device-name NOMBRE` | Limita la consulta al firewall con ese hostname |
| `--device-group DG` | Limita la consulta a los firewalls del Device Group indicado |
| `--output FICHERO.CSV` | Exporta los resultados consolidados a un fichero CSV |
| `--debug` | Activa el modo debug y genera el fichero `debug.txt` |

> `--sn`, `--device-name` y `--device-group` son **mutuamente excluyentes**. `--output` y `--debug` son compatibles con cualquiera de ellos.

### Roles soportados

| Valor interno | Descripción |
|---------------|-------------|
| `superuser` | Super User (acceso total a Panorama/firewall) |
| `superreader` | Super Reader (solo lectura) |
| `deviceadmin` | Device Administrator |
| `devicereader` | Device Reader (solo lectura) |
| `custom` | Rol personalizado (muestra el nombre del perfil) |

## Salida en consola

```
======================================================================
  Panorama Device Admins Checker
======================================================================
  Panorama : https://panorama.ejemplo.com
  Filtro   : Device Group = DG-PRODUCCION
======================================================================

[INFO] Consultando dispositivos conectados a Panorama...
[INFO] 3 dispositivo(s) conectado(s) encontrado(s).
[INFO] Consultando administradores en 1 dispositivo(s)...

[INFO] -> FW-MADRID-01 (007957000675956) ...

======================================================================
  RESULTADO: Administradores por dispositivo
======================================================================

  +- Dispositivo : FW-MADRID-01
  |  Serial      : 007957000675956
  |  Modelo      : PA-VM   PAN-OS: 11.1.6-h10
  |  IP gestion  : 10.3.0.4
  |  Device Group: DG-PRODUCCION
  |  Admins (4):
  |    * admin                     Super User (acceso total)
  |    * apirw                     Super User (acceso total)
  |    * readonly                  Super Reader (solo lectura)
  |    * operador                  Rol personalizado -> perfil: 'securityadmin'
  +-------------------------------------------------------------------

======================================================================
  Total dispositivos consultados : 1
  Total administradores encontrados: 4
======================================================================
[OK] Exportado a CSV: admins.csv
```

## Formato del CSV exportado

Cuando se usa `--output`, se genera un fichero CSV con **una fila por cada combinación dispositivo + administrador**:

| Columna | Descripción |
|---------|-------------|
| `device_name` | Hostname del firewall |
| `serial` | Serial number |
| `model` | Modelo del dispositivo |
| `sw_version` | Versión de PAN-OS |
| `ip` | IP de gestión |
| `device_groups` | Device Groups asignados (separados por `;` si hay varios) |
| `username` | Nombre del administrador |
| `role_type` | Tipo de rol interno (`superuser`, `custom`, etc.) |
| `role_label` | Descripción legible del rol |
| `role_profile` | Nombre del perfil si es un rol personalizado |

**Ejemplo:**
```
device_name,serial,model,sw_version,ip,device_groups,username,role_type,role_label,role_profile
FW-MADRID-01,007957000675956,PA-VM,11.1.6-h10,10.3.0.4,DG-PRODUCCION,admin,superuser,Super User (acceso total),
FW-MADRID-01,007957000675956,PA-VM,11.1.6-h10,10.3.0.4,DG-PRODUCCION,operador,custom,Rol personalizado,securityadmin
```

---

## Modo debug

El flag `--debug` genera el fichero **`debug.txt`** en el directorio de trabajo con un registro completo de la ejecución. Es la herramienta principal para diagnosticar cualquier problema con el script.

### Activación

```bash
python 03-pan_device_admins.py --debug
python 03-pan_device_admins.py --device-group DG-CORP --output admins.csv --debug
```

Al activarse se muestra en consola:
```
[DEBUG] Modo debug activado → C:\...\Pantools\debug.txt
```

Y al finalizar:
```
[DEBUG] Log guardado en: C:\...\Pantools\debug.txt
```

### Contenido del fichero `debug.txt`

El fichero se **sobreescribe** en cada ejecución con `--debug`. Incluye:

| Sección | Qué registra |
|---------|--------------|
| Cabecera de sesión | Fecha/hora de inicio, URL de Panorama |
| `[MAIN]` | Argumentos recibidos, paso de ejecución actual |
| `[API] REQUEST` | URL completa, todos los parámetros enviados (la API Key se oculta como `***REDACTED***`) |
| `[API] RESPONSE` | HTTP status code y cuerpo XML completo en bruto |
| `[API]` | Estado de la respuesta (`success` / error con mensaje) |
| `[DG_MAP]` | XPath usado, entries encontradas y mapa serial→Device Groups construido |
| `[DEVICES]` | Entradas parseadas de `show devices connected`, dict completo de cada dispositivo |
| `[FILTER]` | Filtro aplicado y seriales resultantes |
| `[ADMINS]` | XPath usado por dispositivo, entries de usuario y proceso de detección de rol |
| `[OUTPUT]` | Cada bloque de dispositivo y línea de admin que se imprime en consola |
| `[CSV]` | Cada fila escrita en el fichero CSV |
| Pie de sesión | Fecha/hora de fin |

### Ejemplo de fragmento `debug.txt`

```
========================================================================
  DEBUG SESSION — pan_device_admins.py
  Inicio : 2026-05-13 14:00:00
  Panorama: https://panorama.ejemplo.com
========================================================================

[14:00:00.123] [MAIN] Modo debug activado. Fichero de log: C:\...\debug.txt
[14:00:00.124] [MAIN] Argumentos recibidos: sn=None device_name=None device_group='DG-CORP' output='admins.csv'
[14:00:00.125] [MAIN] === PASO 1: Obtener dispositivos conectados ===
[14:00:00.126] [DEVICES] Ejecutando: show devices connected

  ┌─ API REQUEST ─────────────────────────────────────────────
  │  URL    : https://panorama.ejemplo.com/api/
  │  type   : op
  │  cmd    : <show><devices><connected/></devices></show>
  │  key    : ***REDACTED***
  └────────────────────────────────────────────────────────────

  ┌─ API RESPONSE ─────────────────────────────────────────────
  │  HTTP Status: 200
  │  Body (raw):
  │    <response status="success"><result><devices>...
  └────────────────────────────────────────────────────────────

[14:00:00.890] [API] Respuesta OK (status=success)
[14:00:00.891] [DEVICES] Entradas de dispositivos en la respuesta: 3
[14:00:00.892] [DEVICES] Dispositivo parseado: {'serial': '007957...', 'name': 'FW-MADRID-01', ...}
...
```

> ⚠️ **Nota de seguridad:** El fichero `debug.txt` contiene las respuestas XML completas de Panorama, incluyendo información de dispositivos y usuarios. **No compartas este fichero** sin revisar su contenido. La API Key nunca se escribe en el log.

---

## Consideraciones de seguridad

- **No subas el `.env` a ningún repositorio.** Añádelo al `.gitignore`.
- El script deshabilita la verificación SSL (`verify=False`) para entornos con certificados auto-firmados. En producción, proporciona el certificado CA con `verify='/ruta/al/ca-bundle.crt'`.
- La API Key tiene el mismo nivel de acceso que el usuario administrador asociado. Usa cuentas con el **mínimo privilegio necesario**.

---

---

# 4. Commit-All Cloud NGFW AWS

Script Python para realizar un **Commit-All** a los Cloud Device Groups de **Palo Alto Cloud NGFW for AWS** gestionados desde Panorama. Descubre automáticamente qué regiones AWS tienen firewalls desplegados, solicita confirmación antes de actuar, y monitoriza el estado del push hasta su finalización.

## Flujo de ejecución

```
FASE 1 — Descubrimiento
  Para cada región AWS configurada:
    → API: show plugins aws cngfw-resources (region=X)
    → Si hay firewalls: guarda el device_group_name
          │
          ▼
FASE 2 — Confirmación + Commit-All
  Muestra resumen de Device Groups encontrados
  Pide confirmación [s/N] al usuario
  Para cada Device Group:
    → API: commit all shared-policy (entry name=DG)
    → Espera COMMIT_DELAY_SECONDS entre peticiones
          │
          ▼
FASE 3 — Monitorización
  Espera inicial POLL_INTERVAL_SECONDS
  Mínimo MIN_POLL_ATTEMPTS consultas garantizadas
  Bucle: consulta estado por región cada POLL_INTERVAL_SECONDS
    → Si last_committed_state == "Committing": sigue esperando
    → Si estado final (Success/Error): registra resultado
          │
          ▼
FASE 4 — Resumen final
  Tabla por región: Device Group | Estado | Fecha último commit
```

## Parámetros configurables

Se editan directamente en el script (sección superior):

| Variable | Por defecto | Descripción |
|----------|-------------|-------------|
| `AWS_REGIONS` | Lista de 20 regiones | Regiones AWS donde buscar Cloud NGFWs desplegados |
| `COMMIT_DELAY_SECONDS` | `2` | Pausa (s) entre peticiones de Commit-All consecutivas |
| `POLL_INTERVAL_SECONDS` | `30` | Intervalo (s) entre consultas de estado del push |
| `MIN_POLL_ATTEMPTS` | `2` | Mínimo de rondas de monitorización garantizadas |
| `TIMEOUT` | `60` | Timeout HTTP para llamadas a Panorama |

## Llamadas API

### Fase 1 — Descubrimiento de Cloud NGFWs por región

| Campo | Valor |
|-------|-------|
| `type` | `op` |
| `cmd` | `<show><plugins><aws><cngfw-resources><tenant-name>All</tenant-name><region>REGION</region><tenant-id>All</tenant-id></cngfw-resources></aws></plugins></show>` |

La respuesta incluye un JSON embebido en el elemento `<msg>`. El script parsea `result.entry` y extrae `device_group_name`. Si `entry` es una cadena vacía (`""`), no hay firewalls en esa región.

### Fase 2 — Commit-All al Device Group

| Campo | Valor |
|-------|-------|
| `type` | `commit` |
| `action` | `all` |
| `cmd` | `<commit-all><shared-policy><device-group><entry name="DG_NAME"/></device-group></shared-policy></commit-all>` |

Panorama devuelve un `job-id` que identifica la tarea encolada.

### Fase 3 — Monitorización del estado

Se reutiliza la misma llamada de descubrimiento (Fase 1) por región. El campo clave es `last_committed_state`:

| Valor | Significado |
|-------|-------------|
| `Committing` | Push en curso, seguir esperando |
| `Success` | Push completado con éxito |
| Cualquier otro | Finalizado con error o estado desconocido |

> ⚠️ Panorama puede tardar unos segundos en actualizar el campo `last_committed_state` a `Committing` tras encolar el job. Por eso se garantizan al menos `MIN_POLL_ATTEMPTS` consultas antes de considerar el commit finalizado.

## Uso

```bash
python 04_Commit-all_cloudaws.py
```

No requiere argumentos. Toda la configuración (regiones, tiempos, etc.) se ajusta editando las variables del bloque **Parámetros configurables** al inicio del script.

## Salida esperada

```
======================================================================
  FASE 1 — Descubrimiento de Cloud NGFWs por región AWS
======================================================================
  Panorama : https://panorama.ejemplo.com
  Regiones a consultar: 20
======================================================================

  [>] Consultando región: us-east-1 ... —  Sin firewalls desplegados
  [>] Consultando región: us-west-2 ... ✓  1 firewall(s) encontrado(s)
  [>] Consultando región: eu-west-1 ... —  Sin firewalls desplegados
  ...

======================================================================
  FASE 2 — Commit-All a Cloud Device Groups
======================================================================

  Se realizará Commit-All a los siguientes 1 Device Group(s):

    • cngfw-aws-testdg  (región/es: us-west-2)

  Pausa entre commits : 2s

  ¿Deseas proceder con el Commit-All? [s/N]: s

  [1/1] Enviando Commit-All → 'cngfw-aws-testdg' ... ✓  Job ID: 1234

  [OK] Todas las peticiones de Commit-All han sido enviadas.

  Esperando 30s antes de iniciar la monitorización...

======================================================================
```

# 5. Pan Policy Test

Script Python que **simula qué regla de seguridad de Panorama aplicaría** a un flujo de tráfico determinado, sin necesidad de acceder al firewall físicamente. Evalúa las reglas en el orden correcto de prioridad de PAN-OS, recorriendo toda la jerarquía de Device Groups.

## ¿Por qué este script?

El `policy test` nativo de Panorama solo funciona si el tráfico ya ha pasado por un firewall real. Este script permite simular la evaluación **directamente desde la configuración de Panorama**, lo que resulta útil para:

- Verificar si una política permitirá o bloqueará un flujo antes de hacer un commit.
- Auditar qué regla aplicaría a un tráfico concreto sin acceso al firewall.
- Troubleshooting de políticas en Device Groups con jerarquía compleja.

## Lógica de evaluación

El script respeta el **orden de evaluación real de PAN-OS** para un Device Group con ancestros:

```
1. shared              / pre-rulebase
2. DG ancestro raíz    / pre-rulebase   <- de más lejano a más cercano
3. DG ancestro N       / pre-rulebase
4. DG objetivo         / pre-rulebase
5. DG objetivo         / post-rulebase
6. DG ancestro N       / post-rulebase  <- de más cercano a más lejano
7. DG ancestro raíz    / post-rulebase
8. shared              / post-rulebase
```

La primera regla que haga match es la que se devuelve. Si ninguna hace match, se aplica la **denegación implícita** de PAN-OS.

---

## Jerarquía de Device Groups (`STATIC_DG_PARENT_MAP`)

La jerarquía se define mediante un mapa estático en el script. **Debe mantenerse actualizado** cuando cambie la estructura en Panorama:

```python
STATIC_DG_PARENT_MAP = {
    "US":    "America",
    "LATAM": "America",
    "UK":    "Europe",
    # Los DGs raíz (America, Europe) no aparecen: su padre es implícitamente shared
}
```

Para la estructura `Shared -> America -> US`, la cadena de evaluación sería:
```
shared/pre -> America/pre -> US/pre -> US/post -> America/post -> shared/post
```


## Lógica de evaluación de puertos y servicios

El script maneja cuatro tipos de campo `service` en las reglas:

### 1. `service = any`

El puerto no se filtra. Se verifica únicamente **compatibilidad de protocolo** con la aplicación (p. ej., ICMP no hará match en una regla con `app=dns`).

### 2. `service = <objeto concreto>`

El objeto se resuelve contra los objetos de servicio descargados de Panorama (shared + DG ancestros + DG objetivo).

Los dos servicios **predefinidos de PAN-OS** se incluyen siempre, aunque no aparezcan en la config XML:

| Nombre | Proto | Puerto |
|--------|-------|--------|
| `service-http`  | TCP | 80  |
| `service-https` | TCP | 443 |

### 3. `service = application-default` con app específica (no `any`)

El firewall usa los puertos por defecto del App-ID de la aplicación. El comportamiento del script depende de si el usuario especificó `--app`:

| Situación | Comportamiento |
|-----------|----------------|
| `--app openai` especificado | Comprueba si (proto, puerto) coincide con los defaults de `openai` |
| `--ignore-app` especificado | Permisivo — el usuario ignora la app, no se filtran puertos |
| **Sin `--app`** (caso habitual) | **NO hace match** — sin saber qué clasificará App-ID, no se puede determinar si la regla aplica |

> **Rationale:** Una regla `app=openai / service=application-default` solo aplica si el firewall identifica el tráfico como `openai`. Sin especificar la aplicación, no es posible predecir el comportamiento del App-ID. Forzar match en este caso generaría falsos positivos.

**Ejemplos con una regla `app=openai / service=application-default`:**

```bash
# SIN --app: NO match (App-ID no predecible)
python 05_pan_policy_test.py --device-group US --dst-port tcp/443

# CON --app openai, puerto en defaults (80/443): MATCH
python 05_pan_policy_test.py --device-group US --dst-port tcp/443 --app openai

# CON --app openai, puerto NO en defaults: NO match
python 05_pan_policy_test.py --device-group US --dst-port tcp/8080 --app openai

# CON --ignore-app: MATCH (permisivo)
python 05_pan_policy_test.py --device-group US --dst-port tcp/443 --ignore-app
```

### 4. `service = application-default` con `app = any`

Se trata como permisivo (cualquier puerto puede hacer match).

---

## Puertos por defecto de aplicaciones (`_APP_DEFAULT`)

El script incluye un mapa interno de puertos por defecto para las aplicaciones más comunes. Se usa para validar `service=application-default` cuando se especifica `--app`.

Categorías cubiertas: ICMP, DNS, DHCP, NTP, SNMP, TFTP, Syslog, RADIUS, TACACS, LDAP, HTTP/HTTPS/SSL, FTP, SSH, Telnet, correo (SMTP/IMAP/POP3), RDP, SMB, bases de datos (MSSQL, MySQL, Oracle, PostgreSQL, Redis), VPN (IPsec, OpenVPN), VoIP (SIP, RTP), Kerberos, NFS, BGP, y un amplio set de **aplicaciones SaaS** (OpenAI, Google, Microsoft 365, Teams, Zoom, Slack, GitHub, AWS, Azure, etc.).

Para aplicaciones **no presentes en el mapa** con `application-default`:

| Protocolo | Puerto | Resultado |
|-----------|--------|-----------|
| TCP | 80 o 443 | MATCH (puertos web estándar) |
| TCP | Otro puerto | NO match |
| UDP o ICMP | Cualquiera | NO match (apps desconocidas se asumen TCP/web) |
| Sin proto/puerto | — | MATCH (sin información, no se filtra) |

Para añadir una aplicación al mapa, edita `_APP_DEFAULT` en el script:
```python
"mi-app": [("tcp", {8443, 9000})],
```

---

## Lógica de URL Category (`--url`)

> **Nota técnica:** El campo URL Category en las reglas de seguridad se almacena en el XML como `<category>`, **no** como `<url-category>`. El tag `<url-category>` se usa en los perfiles de URL Filtering, que es algo diferente.

Cuando se especifica `--url`:

1. Se extrae el hostname/dominio de la URL indicada.
2. Para cada regla evaluada, se lee su campo `<category>` (URL Category).
3. Comportamiento según el valor del campo:

| Valor en regla | Comportamiento |
|----------------|----------------|
| Vacío o `any` | Pasa sin restricción |
| **Custom URL Category** (configurada en Panorama) | Se descarga su contenido y se comprueba si el dominio coincide |
| **Categoría predefinida PAN-OS** (ej. `social-networking`) | No resoluble sin PAN-DB — se trata como coincidencia posible |

Las Custom URL Categories se descargan de todos los scopes relevantes (shared + DG ancestros + DG objetivo).

### Patrones de URL soportados en Custom URL Categories

| Patrón | Coincide con |
|--------|--------------|
| `google.com` | `google.com` y cualquier subdominio |
| `*.google.com` | Solo subdominios (`www.google.com`), **no** `google.com` en sí |
| `.google.com` | Equivalente PAN-OS a `*.google.com` |
| `google.com/maps` | Solo se compara la parte host (`google.com`) |

---

## Argumentos

| Argumento | Obligatorio | Descripción | Ejemplo |
|-----------|:-----------:|-------------|--------|
| `--device-group` | ✅ | Device Group objetivo | `US` |
| `--src-ip` | ❌ | IP de origen | `10.1.1.1` |
| `--dst-ip` | ❌ | IP de destino | `8.8.8.8` |
| `--src-port` | ❌ | Puerto de origen | `tcp/1024`, `udp/53`, `1024` |
| `--dst-port` | ❌ | Puerto de destino | `tcp/443`, `udp/53`, `443` |
| `--src-zone` | ❌ | Zona de origen | `trust` |
| `--dst-zone` | ❌ | Zona de destino | `untrust` |
| `--app` | ❌ | Aplicación PAN-OS (necesario para evaluar `application-default` correctamente) | `ssl`, `dns`, `openai` |
| `--ignore-app` | ❌ | Ignora el campo application al evaluar | — |
| `--url` | ❌ | URL/dominio para comparar con url-category de las reglas | `https://google.com` |
| `--output` | ❌ | Guardar resultado en fichero de texto | `resultado.txt` |
| `--debug` | ❌ | Traza detallada en `debug.txt` | — |
| `--debug-stdout` | ❌ | Debug en consola además de fichero | — |

---

## Uso

```bash
# Tráfico DNS (UDP/53)
python 05_pan_policy_test.py --device-group US --src-ip 10.1.1.1 --dst-ip 8.8.8.8 --dst-port udp/53

# Tráfico HTTPS genérico (reglas con application-default+app específica serán descartadas)
python 05_pan_policy_test.py --device-group US --src-ip 10.1.1.50 --dst-ip 8.8.8.8 --dst-port tcp/443

# Tráfico HTTPS con aplicación explícita (evalúa application-default correctamente)
python 05_pan_policy_test.py --device-group US --src-ip 10.1.1.50 --dst-ip 8.8.8.8 --dst-port tcp/443 --app ssl

# Tráfico HTTPS con URL (filtra por url-category de las reglas)
python 05_pan_policy_test.py --device-group US --src-ip 10.0.0.1 --dst-ip 8.8.8.8 --dst-port tcp/443 --url https://www.microsoft.com

# Por zonas sin especificar IPs
python 05_pan_policy_test.py --device-group US --src-zone trust --dst-zone untrust --app ssl

# Ignorar la aplicación (útil si no se conoce el App-ID)
python 05_pan_policy_test.py --device-group US --src-ip 10.0.0.1 --dst-ip 8.8.8.8 --dst-port tcp/443 --ignore-app

# Guardar resultado y activar debug
python 05_pan_policy_test.py --device-group US --src-ip 10.0.0.1 --dst-ip 8.8.8.8 --dst-port tcp/443 --output resultado.txt --debug
```

---

## Salida de ejemplo

```
========================================================================
  Panorama Policy Test — Regla aplicable
========================================================================
  Panorama     : https://panorama.ejemplo.com
  Device Group : US
  Jerarquia    : shared -> America -> US
  IP origen    : 10.1.1.50
  IP destino   : 8.8.8.8
  Puerto dest  : tcp/443
  URL          : www.microsoft.com
========================================================================

[INFO] Orden evaluacion: shared/pre -> America/pre -> US/pre -> US/post -> America/post -> shared/post

[INFO] Cargando objetos de servicio...
  [shared] 12 servicio(s)
  [America] 0 servicio(s)
  [US] 1 servicio(s)

[INFO] Cargando custom URL categories...
  [shared] 1 categoria(s)
  [America] 1 categoria(s)
  [US] 0 categoria(s)

[INFO] Evaluando reglas...
  [shared] pre-rulebase ... 13 regla(s)
  [America] pre-rulebase ... 3 regla(s)

========================================================================
  RESULTADO: [ALLOW] ALLOW  Primera regla que aplica:

  Nombre       : Prueba https
  Ambito       : America / pre-rulebase
  Accion       : ALLOW
  Zona origen  : any
  Zona destino : any
  Source       : any
  Destination  : 8.8.8.8
  Aplicacion   : any
  Servicio     : service-https
  URL Category : Whitelist_America
  Perfil seg.  : (sin perfil)
  Tags         : (sin tags)
========================================================================
```

---

## Campos mostrados en el resultado

| Campo | Descripción |
|-------|-------------|
| `Nombre` | Nombre de la regla que hace match |
| `Ambito` | Device Group y rulebase donde está la regla |
| `Accion` | `ALLOW` o `DENY` |
| `Zona origen / destino` | Zonas configuradas en la regla |
| `Source / Destination` | IPs/objetos de origen y destino |
| `Aplicacion` | Aplicaciones configuradas en la regla |
| `Servicio` | Servicio(s) configurados (`any`, `application-default`, objeto concreto) |
| `URL Category` | URL categories configuradas en la regla (`any` si no tiene) |
| `Perfil seg.` | Grupo de perfiles de seguridad asignado |
| `Tags` | Tags configurados en la regla |

---

## Modo debug

El flag `--debug` genera `debug.txt` con la traza completa de evaluación:

```bash
python 05_pan_policy_test.py --device-group US --dst-port tcp/443 --debug
```

El fichero incluye por cada regla evaluada: todos los checks realizados y la razón de descarte si no hace match. Para ver el debug también en consola:

```bash
python 05_pan_policy_test.py --device-group US --dst-port tcp/443 --debug --debug-stdout
```

---

## Limitaciones conocidas

| Limitación | Detalle |
|------------|---------|
| **IPs en address objects** | Si una regla usa objetos de dirección en lugar de IPs literales, el script compara el nombre del objeto, no la IP subyacente. Combinar `--src-ip`/`--dst-ip` con `--src-zone`/`--dst-zone` mejora la precisión. |
| **`application-default` sin `--app`** | Las reglas con `service=application-default` y apps específicas se descartan si no se especifica `--app`. Comportamiento intencional para evitar falsos positivos. |
| **Categorías URL predefinidas** | Las categorías predefinidas de PAN-OS (`social-networking`, `malware`, etc.) no están en la config XML y no se resuelven sin PAN-DB. Se tratan como coincidencia posible. |
| **Apps desconocidas en `_APP_DEFAULT`** | Apps no presentes en el mapa interno asumen puertos web estándar (tcp/80, tcp/443) para `application-default`. Añade la app a `_APP_DEFAULT` en el script si necesitas precisión. |
| **Jerarquía estática** | `STATIC_DG_PARENT_MAP` debe actualizarse manualmente cuando cambie la jerarquía de Device Groups en Panorama. |
| **Solo security rules** | El script evalúa únicamente reglas de seguridad. No considera NAT, QoS, PBF ni otras políticas de PAN-OS. |
